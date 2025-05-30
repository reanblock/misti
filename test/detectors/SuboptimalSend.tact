const FALSE_CONSTANT: Bool = false;

contract A { init() {} }
contract B {
    owner: Address;
    init(owner: Address) { self.owner = owner; }
    receive() {
        let init = initOf A();

        // send -> deploy
        send(SendParameters{ // Bad: Prefer deploy
            to: contractAddress(init),
            code: init.code,
            data: init.data,
            value: 0,
            body: beginCell().endCell(),
        });
        send(SendParameters{ // Bad: Prefer deploy
            to: contractAddress(init),
            code: init.code,
            value: 0,
            body: beginCell().endCell(),
        });

        // send -> message
        send(SendParameters{ // Bad: Prefer message
            to: contractAddress(init),
            value: 0,
            body: beginCell().endCell(),
        });
        send(SendParameters{ // OK: Has `data` field
            to: contractAddress(init),
            data: init.data,
            value: 0,
            body: beginCell().endCell(),
        });

        // send -> cashback
        send(SendParameters{ // Bad: Prefer cashback
            to: contractAddress(init),
            mode: SendRemainingValue | SendIgnoreErrors,
            value: 0,
            body: beginCell().endCell(),
        });
        send(SendParameters{ // Bad: Prefer cashback
            to: contractAddress(init),
            mode: SendIgnoreErrors | SendRemainingValue,
            value: 0,
            body: beginCell().endCell(),
        });
        send(SendParameters{ // Bad: Prefer cashback
            to: contractAddress(init),
            mode: SendIgnoreErrors + SendRemainingValue,
            value: 0,
            body: beginCell().endCell(),
        });

        // message -> cashback
        message(MessageParameters{ // Bad: Prefer cashback
            to: contractAddress(init),
            mode: SendRemainingValue | SendIgnoreErrors,
            value: 0,
            body: null,
        });
        message(MessageParameters{ // Bad: Prefer cashback
            to: contractAddress(init),
            mode: SendRemainingValue | SendIgnoreErrors,
            value: 0,
            body: null,
            bounce: false,
        });
        message(MessageParameters{ // Bad: Prefer cashback
            to: contractAddress(init),
            mode: SendRemainingValue | SendIgnoreErrors,
            value: 0,
        });
        message(MessageParameters{ // OK
            to: contractAddress(init),
            value: 0,
            body: beginCell().endCell(),
        });
        message(MessageParameters{ // OK
            to: contractAddress(init),
            mode: SendIgnoreErrors,
            value: 0,
            body: beginCell().endCell(),
        });
        message(MessageParameters{ // OK
            to: contractAddress(init),
            mode: SendRemainingValue,
            value: 0,
            body: beginCell().endCell(),
        });
        message(MessageParameters{ // OK
            to: contractAddress(init),
            value: 0,
            body: beginCell().endCell(),
        });
        message(MessageParameters { // OK: Issue #366
            body: emptyCell(),
            to: sender(),
            value: 0,
            mode: SendRemainingValue | SendIgnoreErrors,
        });
        message(MessageParameters { // OK: Issue #366
            bounce: true,
            to: sender(),
            value: 0,
            mode: SendRemainingValue | SendIgnoreErrors,
        });

        let body: Cell = beginCell().endCell();
        // self.forward -> self.reply
        self.forward(sender(), body, true, null);
        // self.forward -> self.notify
        self.forward(sender(), body, false, null);
    }
}
