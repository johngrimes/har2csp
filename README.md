# har2csp

`har2csp` is a command-line tool that generates Content Security Policy (CSP) headers from HTTP Archive (HAR) files. It analyzes the network requests in the HAR file and generates CSP directives that allow those requests, helping you to create a CSP for your website that doesn't break anything.

## Installation

```bash
pip install har2csp
```

## Usage

```bash
har2csp [-h] [-s SELF_URL] har_file_path
```

### Positional Arguments

- `har_file_path`: The path to the HAR file to generate CSP directives from.

### Optional Arguments

- `-h, --help`: Show a help message and exit.
- `-s SELF_URL, --self-url SELF_URL`: The URL of the website that the HAR file was recorded from. Any requests to this URL will be ignored when generating the CSP directives.

## Example

```bash
har2csp -s https://www.example.com example.har
```

This command will generate CSP directives from `example.har`, ignoring any requests to `https://www.example.com`. The directives will be printed to the console.

## License

This project is licensed under the terms of the [Apache 2.0 Licence](./LICENSE).