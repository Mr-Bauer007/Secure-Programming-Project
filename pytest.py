import io
import json
import pytest
from app import app

# ✅ Correct header key based on app.py
API_HEADERS = {
    "x-api-key": "my-super-secret-api-key"
}

def test_encrypt_file():
    tester = app.test_client()
    file_content = b"This is a test file"
    file = io.BytesIO(file_content)
    file.name = "testfile.txt"

    data = {
        "file": (file, file.name),
        "password": "test123"
    }

    response = tester.post("/encrypt", data=data, content_type="multipart/form-data", headers=API_HEADERS)
    assert response.status_code == 200
    assert b"File encrypted successfully" in response.data

def test_encrypt_message():
    tester = app.test_client()
    payload = {
        "message": "Hello World!",
        "password": "secret"
    }

    response = tester.post("/encrypt", data=json.dumps(payload), content_type="application/json", headers=API_HEADERS)
    assert response.status_code == 200
    assert "encrypted_data" in response.get_json()

def test_decrypt_with_wrong_password():
    tester = app.test_client()

    # Encrypt
    message = "Secret message"
    password = "right-password"
    enc_response = tester.post("/encrypt", json={"message": message, "password": password}, headers=API_HEADERS)
    encrypted_data = enc_response.get_json()["encrypted_data"]

    # Try wrong password
    dec_response = tester.post("/decrypt", json={"encrypted_data": encrypted_data, "password": "wrong-password"}, headers=API_HEADERS)
    assert dec_response.status_code == 400
    assert b"Decryption failed" in dec_response.data

def test_decrypt_file_with_non_encrypted_file():
    tester = app.test_client()
    file = io.BytesIO(b"This is not encrypted")
    file.name = "not_encrypted.txt"

    response = tester.post("/decrypt-file", data={"file": (file, file.name), "password": "any"}, content_type="multipart/form-data", headers=API_HEADERS)
    assert response.status_code == 400
    assert b"Invalid file format" in response.data

def test_decrypt_file_missing_password():
    tester = app.test_client()
    file = io.BytesIO(b"some encrypted data")
    file.name = "something.enc"

    response = tester.post("/decrypt-file", data={"file": (file, file.name)}, content_type="multipart/form-data", headers=API_HEADERS)
    assert response.status_code == 400
    assert b"Missing file or password" in response.data

def test_download_decrypted_file():
    tester = app.test_client()
    file_content = b"File to encrypt and decrypt"
    file = io.BytesIO(file_content)
    file.name = "downloadable.txt"

    # Encrypt
    enc_response = tester.post("/encrypt", data={"file": (file, file.name), "password": "mypassword"}, content_type="multipart/form-data", headers=API_HEADERS)
    assert enc_response.status_code == 200
    download_url = enc_response.get_json()["download_url"]

    # Try downloading
    dl_response = tester.get(download_url, headers=API_HEADERS)
    assert dl_response.status_code == 200


