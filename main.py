import os

# Function to write to a file with error handling

def write_to_file(filepath, content):
    try:
        with open(filepath, 'w') as file:
            file.write(content)
        # Verification
        if not os.path.isfile(filepath):
            raise Exception('File write verification failed: File does not exist after writing.')
        print('File written successfully.')
    except Exception as e:
        print(f'Error occurred: {e}')

# Example usage
write_to_file('output.txt', 'Hello, World!')
