import { AstDetector, Category, DetectorSeverity, Severity } from "../detector";
import { CompilationUnit } from "../../internals/ir";
import { MistiTactWarning, WarningDescription } from "../../internals/warnings";
import { forEachStatement, forEachExpression, collectMutations, isSendCall } from "../../internals/tact";
import { 
  AstExpression, 
  AstStatement, 
  idText, 
  AstStaticCall,
  AstMethodCall,
  AstFieldAccess,
  AstId,
  AstContract,
  AstFunctionDef,
  AstReceiver,
  AstFunctionDecl
} from "@tact-lang/compiler/dist/grammar/ast";
import { SrcInfo } from "@tact-lang/compiler/dist/errors";
import { CallGraph, Effect } from "../../internals/ir";
import { mutationNames } from "../../internals/tact/util";

/**
 * A detector that identifies potential race conditions in Actor model smart contracts.
 * 
 * ## Why is it bad?
 * In Actor model smart contracts, race conditions can occur when:
 * 1. A contract stores message data (like query_id) in state variables
 * 2. Sends an async message to another contract
 * 3. The state can be modified by other incoming messages before the response arrives
 * 
 * This can lead to:
 * - Transaction failures when verification against changed state fails
 * - Logic errors and unexpected behavior
 * - Security vulnerabilities if critical state is overwritten
 * 
 * ## Example
 * ```tact
 * contract A {
 *     query_id: Int = 0;
 *     
 *     receive(msg: Request) {
 *         self.query_id = msg.query_id;  // Store query_id
 *         send(...);                      // Send async message
 *         // Another message can arrive here and change query_id!
 *     }
 *     
 *     receive(msg: Response) {
 *         if (msg.query_id != self.query_id) {  // May fail due to race
 *             throw("Invalid query_id");
 *         }
 *     }
 * }
 * ```
 * 
 * Use local variables or message-specific storage to avoid race conditions.
 */
export class RaceCondition extends AstDetector {
  severity = DetectorSeverity.High as Severity;
  category = Category.SECURITY;

  async check(cu: CompilationUnit): Promise<MistiTactWarning[]> {
    const warnings: MistiTactWarning[] = [];
    
    // Track state variables accessed by each function
    const functionStateAccess = new Map<string, {
      reads: Set<string>,
      writes: Set<string>,
      sends: boolean,
      node: AstFunctionDef | AstReceiver,
      contract: string
    }>();

    // Track which state variables are accessed across multiple message handlers
    const stateAccessByVariable = new Map<string, Set<string>>();

    // Analyze each contract
    for (const contract of cu.ast.getContracts()) {
      const contractName = idText(contract.name);
      
      // Collect all state fields
      const stateFields = new Set<string>();
      for (const decl of contract.declarations) {
        if (decl.kind === "field_decl") {
          stateFields.add(idText(decl.name));
        }
      }

      // Analyze each function/receiver
      for (const decl of contract.declarations) {
        if (decl.kind === "function_def" || decl.kind === "receiver") {
          const funcName = this.getFunctionName(decl, contractName);
          const stateReads = new Set<string>();
          const stateWrites = new Set<string>();
          let hasSend = false;

          // Check for sends in the function
          if (decl.kind === "function_def") {
            const nodeId = cu.callGraph.getNodeIdByName(funcName);
            if (nodeId !== undefined) {
              const node = cu.callGraph.getNode(nodeId);
              if (node && node.hasEffect(Effect.Send)) {
                hasSend = true;
              }
            }
          }

          // Analyze statements for state access and sends
          forEachStatement(decl, (stmt) => {
            // Check for direct sends
            forEachExpression(stmt, (expr) => {
              if (isSendCall(expr)) {
                hasSend = true;
              }
              
              // Track state reads
              if (this.isStateRead(expr, stateFields)) {
                const fieldName = this.getAccessedField(expr);
                if (fieldName) {
                  stateReads.add(fieldName);
                }
              }
            });

            // Check for state mutations
            const mutations = collectMutations(stmt);
            if (mutations && mutations.mutatedFields.length > 0) {
              for (const fieldName of mutationNames(mutations)) {
                if (stateFields.has(fieldName)) {
                  stateWrites.add(fieldName);
                }
              }
            }
          });

          // Store function analysis results
          if (stateReads.size > 0 || stateWrites.size > 0) {
            functionStateAccess.set(funcName, {
              reads: stateReads,
              writes: stateWrites,
              sends: hasSend,
              node: decl,
              contract: contractName
            });

            // Track which functions access each state variable
            for (const field of [...stateReads, ...stateWrites]) {
              if (!stateAccessByVariable.has(field)) {
                stateAccessByVariable.set(field, new Set());
              }
              stateAccessByVariable.get(field)!.add(funcName);
            }
          }
        }
      }
    }

    // Detect potential race conditions
    for (const [funcName, access] of functionStateAccess) {
      // Pattern 1: Function that writes state and sends messages
      if (access.sends && access.writes.size > 0) {
        for (const writtenField of access.writes) {
          // Check if this field is accessed by other message handlers
          const accessors = stateAccessByVariable.get(writtenField) || new Set();
          const otherAccessors = Array.from(accessors).filter(f => f !== funcName);
          
          if (otherAccessors.length > 0) {
            // Check if any of the other accessors are receivers or can be called externally
            const externalAccessors = otherAccessors.filter(accessor => {
              const accessInfo = functionStateAccess.get(accessor);
              return accessInfo && (
                accessor.includes("__receiver_") || // Is a receiver
                accessor.includes("__init__") ||     // Is init
                this.isExternallyCallable(accessor, accessInfo.contract, cu)
              );
            });

            if (externalAccessors.length > 0) {
              warnings.push(this.makeWarning(
                `Potential race condition: Function "${this.getDisplayName(funcName)}" writes to state variable "${writtenField}" and sends messages. ` +
                `This variable is also accessed by: ${externalAccessors.map(f => this.getDisplayName(f)).join(", ")}. ` +
                `Other messages may arrive and modify this state between send and response.`,
                access.node.loc,
                {
                  suggestion: `Consider using local variables or message-specific storage instead of shared state for values that must remain consistent across async message flows.`,
                }
              ));
            }
          }
        }
      }

      // Pattern 2: Receiver that reads state that could be modified by other receivers
      if (funcName.includes("__receiver_") && access.reads.size > 0) {
        for (const readField of access.reads) {
          const writers = Array.from(stateAccessByVariable.get(readField) || new Set())
            .filter(f => f !== funcName && functionStateAccess.get(f)?.writes.has(readField));
          
          const sendingWriters = writers.filter(w => functionStateAccess.get(w)?.sends);
          
          if (sendingWriters.length > 0) {
            warnings.push(this.makeWarning(
              `Potential race condition: Receiver "${this.getDisplayName(funcName)}" reads state variable "${readField}" ` +
              `that is written by message-sending functions: ${sendingWriters.map(f => this.getDisplayName(f)).join(", ")}. ` +
              `The value may change between when it was set and when this receiver reads it.`,
              access.node.loc,
              {
                suggestion: `Pass necessary data as part of the message instead of relying on shared state that can change.`,
                extraDescription: `This pattern is particularly dangerous with query_id or nonce values that must match between request and response.`
              }
            ));
          }
        }
      }
    }

    return warnings;
  }

  private getFunctionName(decl: AstFunctionDef | AstReceiver, contractName: string): string {
    if (decl.kind === "function_def") {
      return `${contractName}::${idText(decl.name)}`;
    } else {
      // Format receiver name similar to how CallGraph does it
      const receiverType = decl.selector.kind === "internal-comment" 
        ? decl.selector.comment 
        : idText(decl.selector.name);
      return `${contractName}::__receiver_${receiverType}__`;
    }
  }

  private getDisplayName(funcName: string): string {
    // Convert internal names to more readable format
    if (funcName.includes("__receiver_")) {
      const parts = funcName.split("::");
      const receiverPart = parts[1].replace("__receiver_", "").replace("__", "");
      return `${parts[0]}::receive(${receiverPart})`;
    }
    return funcName;
  }

  private isStateRead(expr: AstExpression, stateFields: Set<string>): boolean {
    if (expr.kind === "field_access" && expr.aggregate.kind === "id" && idText(expr.aggregate) === "self") {
      return stateFields.has(idText(expr.field));
    }
    return false;
  }

  private getAccessedField(expr: AstExpression): string | null {
    if (expr.kind === "field_access" && expr.aggregate.kind === "id" && idText(expr.aggregate) === "self") {
      return idText(expr.field);
    }
    return null;
  }

  private isExternallyCallable(funcName: string, contractName: string, cu: CompilationUnit): boolean {
    // Check if the function is public (get methods are always public in Tact)
    const parts = funcName.split("::");
    if (parts.length !== 2) return false;
    
    const methodName = parts[1];
    
    // Get methods are externally callable
    if (methodName.startsWith("get")) return true;
    
    // Check the actual function declaration for visibility
    const contract = cu.ast.getContracts().find(c => idText(c.name) === contractName);
    if (!contract) return false;
    
    for (const decl of contract.declarations) {
      if (decl.kind === "function_def" && idText(decl.name) === methodName) {
        // In Tact, functions without explicit visibility modifiers are internal
        // Only 'get' functions are externally callable
        return idText(decl.name).startsWith("get");
      }
    }
    
    return false;
  }
}