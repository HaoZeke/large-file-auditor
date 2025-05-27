# Large File Auditor

Ensures no large files sneak in, and pin-points the incriminating commit.

## References

- [hywax/github-action-template](https://github.com/hywax/github-action-template/generate).

## Usage

```shell
git clone https://github.com/HaoZeke/large-file-auditor.git
cd github-action-template
pnpm install
```

The template contains the following scripts:

- `build` - Build for production
- `release` - Generate changelog and npm publish
- `lint` - Checks your code for any linting errors
- `test` - Run all tests
- `test:watch` - Run all tests with watch mode
- `test:coverage` - Run all tests with code coverage report
- `typecheck` - Run TypeScript type checking
- `prepare` - Script for setting up husky hooks

## License

[MIT](LICENSE).
