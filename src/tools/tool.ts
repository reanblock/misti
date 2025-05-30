import { ToolOutput } from "../cli/result";
import { MistiContext } from "../internals/context";
import { InternalException } from "../internals/exceptions";
import { CompilationUnit } from "../internals/ir";
import path from "path";

export type ToolName = string;

/**
 * A tool that can be used to extend the functionality of Misti.
 */
export abstract class Tool<T extends Record<string, unknown>> {
  /**
   * User-defined options for the tool merged with the default options.
   */
  protected readonly options: T;

  constructor(
    readonly ctx: MistiContext,
    config: T,
  ) {
    this.options = this.mergeWithDefaults(config);
  }

  /**
   * The unique identifier of the tool.
   */
  get id(): ToolName {
    return this.constructor.name;
  }

  /**
   * The default options for the tool.
   */
  abstract get defaultOptions(): T;

  /**
   * Merges the given config with the default options.
   */
  private mergeWithDefaults(config: T): T {
    return {
      ...this.defaultOptions,
      ...config,
    };
  }

  /**
   * Runs the tool on the given compilation unit.
   * @param cu The compilation unit to run the tool on.
   * @returns The result of the tool.
   */
  public run(cu: CompilationUnit): ToolOutput | never {
    return this.runWithCU(cu);
  }

  /**
   * Runs the tool without any compilation unit.
   * @returns The result of the tool.
   */
  public runStandalone(): ToolOutput | never {
    throw InternalException.make(
      `Tool ${this.id} does not support running without a compilation unit`,
    );
  }

  /**
   * Implement this method if your tool needs a compilation unit.
   * @param cu The compilation unit to run the tool on.
   */
  protected runWithCU(_: CompilationUnit): ToolOutput | never {
    throw InternalException.make(
      `Tool ${this.id} does not support running with a compilation unit`,
    );
  }

  /**
   * Makes a ToolOutput from the given output.
   */
  protected makeOutput(
    cu: CompilationUnit | undefined,
    output: string,
  ): ToolOutput {
    return {
      name: this.id,
      projectName: cu?.projectName,
      output,
    };
  }

  /**
   * Returns a description of the tool and its options.
   */
  abstract getDescription(): string;

  /**
   * Returns a map of option names to their descriptions.
   */
  abstract getOptionDescriptions(): Record<keyof T, string>;

  /**
   * Tests if the Tool could be executed without compilation unit using `runStandalone`.
   */
  public static canRunStandalone(tool: Tool<any>): boolean {
    try {
      const originalMethod = tool.runStandalone;
      return originalMethod !== Tool.prototype.runStandalone;
    } catch {
      return false;
    }
  }
}

// Define the structure of each tool entry in the BuiltInTools map.
interface ToolEntry<T extends Record<string, unknown>> {
  loader: (ctx: MistiContext, options: T) => Promise<Tool<T>>;
}

/**
 * A mapping of tool names to their respective loader functions.
 */
const BuiltInTools: Record<string, ToolEntry<any>> = {
  DumpAst: {
    loader: (ctx: MistiContext, options: any) =>
      import("./dumpAst").then((module) => new module.DumpAst(ctx, options)),
  },
  DumpCfg: {
    loader: (ctx: MistiContext, options: any) =>
      import("./dumpCfg").then((module) => new module.DumpCfg(ctx, options)),
  },
  DumpConfig: {
    loader: (ctx: MistiContext, options: any) =>
      import("./dumpConfig").then(
        (module) => new module.DumpConfig(ctx, options),
      ),
  },
  DumpImports: {
    loader: (ctx: MistiContext, options: any) =>
      import("./dumpImports").then(
        (module) => new module.DumpImports(ctx, options),
      ),
  },
  DumpCallGraph: {
    loader: (ctx: MistiContext, options: any) =>
      import("./dumpCallgraph").then(
        (module) => new module.DumpCallGraph(ctx, options),
      ),
  },
};

/**
 * Asynchronously retrieves a built-in tool by its name.
 * If the tool is found in the BuiltInTools registry, it is loaded and returned;
 * otherwise, a warning is logged and `undefined` is returned.
 *
 * @param ctx Misti context.
 * @param name The name of the tool to retrieve. This name must match a key in the BuiltInTools object.
 * @param options The options to pass to the tool constructor.
 * @returns A Promise that resolves to a Tool instance or `undefined` if the tool cannot be found or fails to load.
 */
export async function findBuiltInTool<T extends Record<string, unknown>>(
  ctx: MistiContext,
  name: string,
  options: T,
): Promise<Tool<T> | undefined> {
  const toolEntry = BuiltInTools[name];
  if (!toolEntry) {
    ctx.logger.warn(`Built-in tool ${name} not found.`);
    return undefined;
  }
  try {
    return await toolEntry.loader(ctx, options);
  } catch (error) {
    ctx.logger.error(`Error loading built-in tool ${name}: ${error}`);
    return undefined;
  }
}

/**
 * Loads an external tool from a module path.
 * @param ctx Misti context
 * @param modulePath Path to the module
 * @param className Name of the tool class to load
 * @param options Options to pass to the tool constructor
 * @returns A Promise that resolves to a Tool instance or undefined if loading failed
 */
export async function loadExternalTool<T extends Record<string, unknown>>(
  ctx: MistiContext,
  modulePath: string,
  className: string,
  options: T,
): Promise<Tool<T> | undefined> {
  let ToolClass;
  let module;
  try {
    const absolutePath = path.resolve(modulePath);
    const relativePath = path.relative(__dirname, absolutePath);
    module = await import(relativePath.replace(path.extname(relativePath), ""));
    ToolClass = module[className];
  } catch (error) {
    ctx.logger.error(`Failed to import module: ${modulePath}`);
    ctx.logger.error(`${error}`);
    return undefined;
  }
  if (!ToolClass) {
    ctx.logger.error(
      `Tool class ${className} not found in module ${modulePath}`,
    );
    return undefined;
  }
  return new ToolClass(ctx, options) as Tool<T>;
}

/**
 * Returns a list of all the available built-in tools.
 * @returns An array of strings representing the names of tools.
 */
export function getAllTools(): string[] {
  return Object.keys(BuiltInTools);
}

/**
 * @returns True if there is a built-in tool with the given name.
 */
export function hasBuiltInTool(name: string): boolean {
  return name in BuiltInTools;
}

/**
 * Generates a help message for all the available tools.
 * @returns A string containing the help message.
 */
export async function generateToolsHelpMessage(): Promise<string> {
  let helpMessage = "Available tools:\n\n";
  for (const [toolName, toolEntry] of Object.entries(BuiltInTools)) {
    const tool = await toolEntry.loader(new MistiContext(undefined), {});
    helpMessage += `* ${toolName}: ${tool.getDescription()}\n`;
    const optionDescriptions = tool.getOptionDescriptions();
    if (Object.keys(optionDescriptions).length > 0)
      helpMessage += "  Options:\n";
    for (const [optionName, description] of Object.entries(
      optionDescriptions,
    )) {
      helpMessage += `  - ${optionName}: ${description}\n`;
    }
    helpMessage += "\n";
  }
  return helpMessage;
}
