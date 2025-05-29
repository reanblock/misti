import { InternalException } from "../../internals/exceptions";
import { Cfg, BasicBlock, CompilationUnit } from "../../internals/ir";
import {
  IntervalJoinSemiLattice,
  JoinSemilattice,
  WideningLattice,
} from "../../internals/lattice";
import { Interval, Num } from "../../internals/numbers";
import { WideningWorklistSolver } from "../../internals/solver";
import { evalToType } from "../../internals/tact";
import {
  AstStatement,
  AstExpression,
  AstNumber,
  idText,
} from "../../internals/tact/imports";
import { findInExpressions } from "../../internals/tact/iterators";
import { Transfer } from "../../internals/transfer";
import { Category, Warning, Severity } from "../../internals/warnings";
import { DataflowDetector } from "../detector";

type Variable = string & { readonly __brand: unique symbol };

type VariableState = Map<Variable, Interval>;

class DivisionByZeroLattice
  implements JoinSemilattice<VariableState>, WideningLattice<VariableState>
{
  private intervalLattice;
  private widenCount = new Map<Variable, number>();
  private readonly WIDENING_THRESHOLD = 3;

  constructor() {
    this.intervalLattice = new IntervalJoinSemiLattice();
  }

  bottom(): VariableState {
    return new Map();
  }

  join(a: VariableState, b: VariableState): VariableState {
    const result = new Map<Variable, Interval>();
    const variables = new Set([...a.keys(), ...b.keys()]);
    for (const variable of variables) {
      const intervalA = a.get(variable) || this.intervalLattice.bottom();
      const intervalB = b.get(variable) || this.intervalLattice.bottom();
      const joinedInterval = this.intervalLattice.join(intervalA, intervalB);
      result.set(variable, joinedInterval);
    }
    return result;
  }

  leq(a: VariableState, b: VariableState): boolean {
    for (const [variable, intervalA] of a.entries()) {
      const intervalB = b.get(variable) || this.intervalLattice.bottom();
      if (!this.intervalLattice.leq(intervalA, intervalB)) {
        return false;
      }
    }
    return true;
  }

  widen(oldState: VariableState, newState: VariableState): VariableState {
    const result = new Map<Variable, Interval>();
    const variables = new Set([...oldState.keys(), ...newState.keys()]);

    for (const variable of variables) {
      const count = (this.widenCount.get(variable) || 0) + 1;
      this.widenCount.set(variable, count);
      const intervalOld =
        oldState.get(variable) || this.intervalLattice.bottom();
      const intervalNew =
        newState.get(variable) || this.intervalLattice.bottom();

      let widenedInterval: Interval;
      if (count > this.WIDENING_THRESHOLD) {
        widenedInterval = IntervalJoinSemiLattice.topValue;
      } else {
        widenedInterval = this.intervalLattice.widen(intervalOld, intervalNew);
      }

      result.set(variable, widenedInterval);
    }
    return result;
  }
}

class DivisionByZeroTransfer implements Transfer<VariableState> {
  transfer(
    inState: VariableState,
    _bb: BasicBlock,
    stmt: AstStatement,
  ): VariableState {
    const outState = new Map(inState);

    if (stmt.kind === "statement_assign") {
      const varName = this.extractVariableName(stmt.path);
      if (varName) {
        const exprInterval = this.evaluateExpression(stmt.expression, inState);
        outState.set(varName as Variable, exprInterval);
      }
    } else if (stmt.kind === "statement_let" && stmt.name.kind === "id") {
      const varName = idText(stmt.name);
      const exprInterval = this.evaluateExpression(stmt.expression, inState);
      outState.set(varName as Variable, exprInterval);
    }

    return outState;
  }

  private extractVariableName(expr: AstExpression): string | null {
    return expr.kind === "id" ? idText(expr) : null;
  }

  private evaluateExpression(
    expr: AstExpression,
    state: VariableState,
  ): Interval {
    if (expr.kind === "number") {
      const exprNum = expr as AstNumber;
      const value = BigInt(exprNum.value);
      return Interval.fromNum(value);
    } else if (expr.kind === "id") {
      const varName = idText(expr) as Variable;
      return state.get(varName) || IntervalJoinSemiLattice.topValue;
    } else if (expr.kind === "op_binary") {
      const leftInterval = this.evaluateExpression(expr.left, state);
      const rightInterval = this.evaluateExpression(expr.right, state);
      switch (expr.op) {
        case "+":
          return leftInterval.plus(rightInterval);
        case "-":
          return leftInterval.minus(rightInterval);
        case "*":
          return leftInterval.times(rightInterval);
        case "/":
          return leftInterval.div(rightInterval);
        default:
          return IntervalJoinSemiLattice.topValue;
      }
    }
    return IntervalJoinSemiLattice.topValue;
  }
}

/**
 * A detector that identifies potential division by zero operations.
 *
 * ## Why is it bad?
 * Division by zero causes runtime errors that will make the contract fail.
 * Even if there are checks preventing zero values, it's better to make
 * the contract more robust by explicitly handling these cases.
 *
 * ## Example
 * ```tact
 * contract Example {
 *     fun calculateRatio(a: Int, b: Int): Int {
 *         // Bad: b could be zero
 *         return a / b;
 *     }
 * }
 * ```
 *
 * Use instead:
 * ```tact
 * contract Example {
 *     fun calculateRatio(a: Int, b: Int): Int {
 *         // OK: Check for zero before division
 *         require(b != 0, "Division by zero");
 *         return a / b;
 *     }
 * }
 * ```
 */
export class DivisionByZero extends DataflowDetector {
  severity = Severity.HIGH;
  category = Category.SECURITY;

  async check(cu: CompilationUnit): Promise<Warning[]> {
    const warnings: Warning[] = [];

    cu.forEachCFG(
      (cfg: Cfg) => {
        const node = cu.ast.getFunction(cfg.id);
        if (node === undefined) {
          return;
        }
        const lattice = new DivisionByZeroLattice();
        const transfer = new DivisionByZeroTransfer();
        const solver = new WideningWorklistSolver<VariableState>(
          cu,
          cfg,
          transfer,
          lattice,
          "forward",
          5,
        );
        const results = solver.solve();
        for (const bb of cfg.nodes) {
          const state = results.getState(bb.idx);
          if (state) {
            this.checkStateForWarnings(cu, state, bb, warnings);
          }
        }
      },
      { includeStdlib: false },
    );
    return warnings;
  }

  private checkStateForWarnings(
    cu: CompilationUnit,
    state: VariableState,
    bb: BasicBlock,
    warnings: Warning[],
  ): void {
    const stmt = cu.ast.getStatement(bb.stmtID);
    if (!stmt) {
      throw InternalException.make(`Cannot find a statement for BB #${bb.idx}`);
    }
    
    findInExpressions(stmt, (expr) => {
      if (expr.kind === "op_binary" && (expr.op === "/" || expr.op === "%")) {
        this.checkDivision(expr, state, warnings);
      }
      return false;
    });
  }

  private checkDivision(
    expr: AstExpression & { kind: "op_binary" },
    state: VariableState,
    warnings: Warning[],
  ): void {
    // Check if divisor is a literal zero
    if (expr.right.kind === "number") {
      const num = evalToType(expr.right, "number");
      if (num && num.kind === "number" && num.value === 0n) {
        warnings.push(
          this.makeWarning(
            "Division by zero",
            expr.loc,
            {
              extraDescription: "This will cause a runtime error",
              suggestion: "Check that the divisor is not zero before dividing",
            },
          ),
        );
        return;
      }
    }

    // Check if divisor is a variable that could be zero
    if (expr.right.kind === "id") {
      const varName = idText(expr.right) as Variable;
      const interval = state.get(varName);
      
      if (interval && this.intervalCouldBeZero(interval)) {
        warnings.push(
          this.makeWarning(
            `Potential division by zero: variable "${varName}" could be zero`,
            expr.loc,
            {
              extraDescription: `Variable value range: ${interval.toString()}`,
              suggestion: "Add a check to ensure the divisor is not zero",
            },
          ),
        );
      }
    }
  }

  private intervalCouldBeZero(interval: Interval): boolean {
    const zero = Num.int(0n);
    // Check if zero is within the interval [low, high]
    return (
      Num.compare(interval.low, zero) <= 0 &&
      Num.compare(interval.high, zero) >= 0
    );
  }
}