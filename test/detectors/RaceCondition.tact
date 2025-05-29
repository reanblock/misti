// Test cases for RaceCondition detector

// TEST 1: Classic race condition with query_id
contract QueryIdRace {
    query_id: Int = 0;
    
    // BAD: Writes query_id and sends message
    receive(msg: Request) {
        self.query_id = msg.query_id;  // Write state
        send(SendParameters{
            to: msg.target,
            value: ton("0.1"),
            body: ForwardRequest{query_id: self.query_id}.toCell()
        });
        // Another message can arrive here and change query_id!
    }
    
    // BAD: Reads query_id that could have been modified
    receive(msg: Response) {
        if (msg.query_id != self.query_id) {  // Read potentially stale state
            throw(123);
        }
    }
}

// TEST 2: Multiple receivers accessing same state
contract SharedStateRace {
    counter: Int = 0;
    lastSender: Address;
    
    // BAD: Writes counter and sends
    receive(msg: Increment) {
        self.counter = self.counter + 1;
        self.lastSender = sender();
        send(SendParameters{
            to: self.owner,
            value: ton("0.05"),
            body: CounterUpdated{value: self.counter}.toCell()
        });
    }
    
    // BAD: Reads counter that increment might be modifying
    receive(msg: GetCounter) {
        self.reply(CounterValue{value: self.counter}.toCell());
    }
    
    // BAD: Also accesses the shared counter
    receive(msg: Reset) {
        self.counter = 0;
    }
}

// TEST 3: State mutation in functions called by receivers
contract IndirectRace {
    nonce: Int = 0;
    
    // BAD: Function that mutates and sends
    fun processRequest() {
        self.nonce = self.nonce + 1;
        send(SendParameters{
            to: self.processor,
            value: ton("0.1"),
            body: ProcessNonce{nonce: self.nonce}.toCell()
        });
    }
    
    receive(msg: StartProcess) {
        self.processRequest();
    }
    
    // BAD: Reads nonce that processRequest might be modifying
    receive(msg: VerifyNonce) {
        require(msg.nonce == self.nonce, "Invalid nonce");
    }
}

// TEST 4: Good pattern - no race condition
contract NoRaceGoodPattern {
    totalProcessed: Int = 0;
    
    // GOOD: Uses local variable for consistency
    receive(msg: Process) {
        let localQueryId = msg.query_id;  // Use local variable
        send(SendParameters{
            to: msg.target,
            value: ton("0.1"),
            body: ProcessRequest{query_id: localQueryId}.toCell()
        });
        self.totalProcessed = self.totalProcessed + 1;  // Safe counter update
    }
    
    // GOOD: Only reads immutable or safely updated state
    get fun getTotalProcessed(): Int {
        return self.totalProcessed;
    }
}

// TEST 5: Complex race with multiple state variables
contract ComplexRace {
    stage: Int = 0;
    participant: Address;
    amount: Int = 0;
    
    // BAD: Multiple state mutations with send
    receive(msg: InitiateTransfer) {
        self.stage = 1;
        self.participant = msg.target;
        self.amount = msg.amount;
        
        send(SendParameters{
            to: self.participant,
            value: ton("0.1"),
            body: TransferInit{
                stage: self.stage,
                amount: self.amount
            }.toCell()
        });
    }
    
    // BAD: Reads multiple potentially stale values
    receive(msg: ConfirmTransfer) {
        require(self.stage == 1, "Wrong stage");
        require(msg.participant == self.participant, "Wrong participant");
        require(msg.amount == self.amount, "Wrong amount");
        
        self.stage = 2;
    }
}

// Required message types for tests
message Request {
    query_id: Int as uint64;
    target: Address;
}

message Response {
    query_id: Int as uint64;
}

message ForwardRequest {
    query_id: Int as uint64;
}

message Increment {}

message GetCounter {}

message Reset {}

message CounterUpdated {
    value: Int as uint32;
}

message CounterValue {
    value: Int as uint32;
}

message StartProcess {}

message ProcessNonce {
    nonce: Int as uint64;
}

message VerifyNonce {
    nonce: Int as uint64;
}

message Process {
    query_id: Int as uint64;
    target: Address;
}

message ProcessRequest {
    query_id: Int as uint64;
}

message InitiateTransfer {
    target: Address;
    amount: Int as coins;
}

message TransferInit {
    stage: Int as uint8;
    amount: Int as coins;
}

message ConfirmTransfer {
    participant: Address;
    amount: Int as coins;
}