# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import argparse
import os
from urllib.parse import urlparse

# Define the list of CSP directives.
CSP_DIRECTIVES = [
    'default-src',
    'script-src',
    'style-src',
    'img-src',
    'connect-src',
    'font-src',
    'object-src',
    'media-src',
    'frame-src',
    'worker-src'
]

# Function to generate CSP directives from a HAR file.
def generate_csp_directives(har_file_path, self_url):
    # Open the HAR file and load the data.
    with open(har_file_path, 'r') as f:
        har_data = json.loads(f.read())

    # Initialize a dictionary to store the CSP directives.
    csp_directives = {directive: set() for directive in CSP_DIRECTIVES}

    # Define a mapping from MIME types to CSP directives.
    mime_directive_map = {
        'text/html': 'default-src',
        'text/css': 'style-src',
        'text/javascript': 'script-src',
        'application/javascript': 'script-src',
        'image/png': 'img-src',
        'image/jpeg': 'img-src',
        'image/gif': 'img-src',
        'application/x-font-ttf': 'font-src',
        'application/font-woff': 'font-src',
        'application/font-woff2': 'font-src',
        'application/octet-stream': 'object-src',
        'text/plain': 'default-src'
    }

    # Iterate over the entries in the HAR data.
    for entry in har_data['log']['entries']:
        url = entry['request']['url']
        parsed_url = urlparse(url)
        # Skip the entry if the URL is the same as the self URL.
        if self_url and (parsed_url.netloc == urlparse(self_url).netloc or parsed_url.netloc == ''):
            continue
        # If the response status is 400 or higher, add the URL to the default-src directive.
        if entry['response']['status'] >= 400:
            csp_directives['default-src'].add(parsed_url.scheme + '://' + parsed_url.netloc)
        # If the response has a content and mimeType field, add the URL to the corresponding directive.
        elif 'content' in entry['response'] and 'mimeType' in entry['response']['content']:
            mime_type = entry['response']['content']['mimeType']
            directive = mime_directive_map.get(mime_type, 'default-src')
            csp_directives[directive].add(parsed_url.scheme + '://' + parsed_url.netloc)
        # If the response does not have a content and mimeType field, determine the directive based on the file extension.
        else:
            extension = os.path.splitext(parsed_url.path)[1]
            if extension:
                extension = extension.lower()
                if extension in ['.js', '.mjs']:
                    directive = 'script-src'
                elif extension in ['.css']:
                    directive = 'style-src'
                elif extension in ['.png', '.jpg', '.jpeg', '.gif']:
                    directive = 'img-src'
                elif extension in ['.ttf', '.woff', '.woff2']:
                    directive = 'font-src'
                else:
                    directive = 'default-src'
                csp_directives[directive].add(parsed_url.scheme + '://' + parsed_url.netloc)

    # Add 'self' to all directives.
    for directive in csp_directives.keys():
        csp_directives[directive].add("'self'")

    return csp_directives

# Main function to parse command line arguments and generate the CSP header.
def main():
    # Initialize the argument parser.
    parser = argparse.ArgumentParser(description='Generate a CSP header from a HAR file.')
    parser.add_argument('har_file_paths', nargs='+', help='The path to the HAR file(s).')
    parser.add_argument('-s', '--self-url', help='The self URL to exclude from the CSP header.')
    args = parser.parse_args()

    # Initialize a dictionary to store the combined CSP directives.
    combined_csp_directives = {directive: set() for directive in CSP_DIRECTIVES}

    # Generate the CSP directives for each HAR file and combine them.
    for har_file_path in args.har_file_paths:
        csp_directives = generate_csp_directives(har_file_path, args.self_url)
        for directive, sources in csp_directives.items():
            combined_csp_directives[directive].update(sources)

    # Generate the CSP header.
    csp_header = ''
    for directive, sources in combined_csp_directives.items():
        if sources:
            if len(sources) > 1 or directive == 'default-src':
                csp_header += directive + ' ' + ' '.join(sources) + '; '

    # Print the CSP header.
    print(csp_header.strip())

if __name__ == "__main__":
    main()