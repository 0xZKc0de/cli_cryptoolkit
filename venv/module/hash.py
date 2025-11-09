import hashlib 

# text = "Hello, World"
# hash_object = hashlib.sha256(text.encode())
# hash_digest = hash_object.hexdigest()
# print(hash_digest ) 

def hash_file(path_file : str) -> str:
    h = hashlib.new("sha256")
    with open(path_file, "rb") as file:
        while True:
            chunk = file.read(1024)
            if chunk == b"":
                break
            h.update(chunk)
    return h.hexdigest()

def verify_integrity(file1 : str, file2 : str):
    hash1, hash2 = hash_file(file1), hash_file(file2)
    
    print(f'\nChecking integrity between {file1} and {file2}')
    
    return "File is intact. No modifications have been made" if hash1 == hash2 else "File has been modified. Possibly unsafe."

if __name__ == "__main__":
    print(f'SHA hash of File is : {hash_file(r"venv\simple_files\simple.txt")}')
    # ----------------------
    print(verify_integrity(r"venv\simple_files\simple.txt", r"venv\simple_files\simple.txt"))