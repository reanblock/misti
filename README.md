# <img src="img/misti.svg" alt="Misti Logo" width="32"/> Misti
Misti is a static analysis tool designed for smart contracts on the [TON blockchain](https://ton.org/) written in [Tact](https://tact-lang.org/).

### Build and Develop from source

1. Clone this repo
2. Build it: `cd misti && yarn install && yarn gen && yarn build`
3. Use it in your Tact project: `cd /path/to/tact/project && yarn add file:/path/to/misti` or use npm `npm install -D file:/path/to/misti`.

### Add example `ImplicitInit` detector to default detectors

1. Copy the example `ImplicitInit` detector to `src/detectors/builtin/` folder: `cp examples/implicit-init/implicitInit.ts src/detectors/builtin/`
1. Remove `/src/` from any import paths, for example change `../../src/detectors/detector` to `../../detectors/detector`.
1. Add the new Detector to the existing list in `src/detectors/detector.ts` file.
1. Build the misti project `yarn build`. 
1. Add the local dependency of misti to the target project `npm install -D file:../misti`
1. Test the detector in the target project `npx misti --enabled-detectors ImplicitInit contracts/target.tact`

#### Features
- **Code Analysis**: Built-in suite of [38 detectors](https://nowarp.io/tools/misti/docs/next/detectors) for identifying security vulnerabilities and anti-patterns.
- **CI/CD Integration**:
  [Integrate](https://nowarp.io/tools/misti/docs/tutorial/ci-cd) Misti into your CI/CD pipeline to ensure continuous code quality checks.
- **Custom Detectors**: Create [custom detectors](https://nowarp.io/tools/misti/docs/hacking/custom-detector) to solve specific problems in your code or to provide a thorough security review if you are an auditor.
- **Custom Tools**: Extend Misti with your own tools for custom analysis and reporting capabilities.

## Getting Started
1. *(optional)* [Install Soufflé](https://souffle-lang.github.io/install) to enable more built-in detectors.
2. Install Misti:
```bash
npm install -g @nowarp/misti
```

3. Run Misti by specifying a Tact contract, project config, or directory to check:
```bash
misti path/to/src/contracts
```

4. Use built-in tools:
```bash
misti path/to/src/contracts -t DumpAst
```

5. Use external tools:
```bash
misti path/to/src/contracts -t /path/to/custom-tool.js:CustomToolClassName
```

See [Misti Configuration](https://nowarp.io/tools/misti/docs/tutorial/getting-started/) for available options, or [Developing Misti](https://nowarp.io/tools/misti/docs/next/hacking/developing-misti) for advanced instructions. Blueprint users should refer to the [appropriate documentation page](https://nowarp.io/tools/misti/docs/tutorial/blueprint).

## Resources
- **[nowarp.io](https://nowarp.io)**: We are doing other TON Security stuff beyond Misti.
- **[Documentation](https://nowarp.io/tools/misti/docs)**: Comprehensive guide on detectors, architecture, and development.
- **[API Reference](https://nowarp.io/api/misti/)**: Useful for contributors or developers creating custom detectors.
- **[Blueprint Plugin](https://github.com/nowarp/blueprint-misti)**: A plugin for the Blueprint Framework to enhance your workflow.
- **[Community Chat](https://t.me/tonsec_chat)**: Join the conversation and get help with Misti-related questions.
