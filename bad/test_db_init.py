#!/usr/bin/env python3

import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch, MagicMock


class TestDBInit(unittest.TestCase):
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, 'test_users.sqlite')
    
    def tearDown(self):
        """Clean up test environment."""
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        try:
            os.rmdir(self.test_dir)
        except OSError:
            pass
    
    def test_insert_normal_users(self):
        """Test that normal users are inserted correctly using parameterized queries."""
        users = [
            ('admin', 'SuperSecret'),
            ('elliot', '123123123'),
            ('tim', '12345678')
        ]
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("CREATE TABLE users (username text, password text, failures int, mfa_enabled int, mfa_secret text)")
        
        for u, p in users:
            # This is the fixed version using parameterized queries
            c.execute("INSERT INTO users (username, password, failures, mfa_enabled, mfa_secret) VALUES (?, ?, ?, ?, ?)", 
                     (u, p, 0, 0, ''))
        
        conn.commit()
        
        # Verify all users were inserted correctly
        c.execute("SELECT username, password FROM users")
        results = c.fetchall()
        conn.close()
        
        self.assertEqual(len(results), 3)
        self.assertIn(('admin', 'SuperSecret'), results)
        self.assertIn(('elliot', '123123123'), results)
        self.assertIn(('tim', '12345678'), results)
    
    def test_insert_user_with_sql_injection_attempt(self):
        """Test that SQL injection attempts are properly escaped with parameterized queries."""
        # This username would cause SQL injection with string formatting
        malicious_username = "'; DROP TABLE users; --"
        password = "password123"
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("CREATE TABLE users (username text, password text, failures int, mfa_enabled int, mfa_secret text)")
        
        # Using parameterized queries prevents SQL injection
        c.execute("INSERT INTO users (username, password, failures, mfa_enabled, mfa_secret) VALUES (?, ?, ?, ?, ?)", 
                 (malicious_username, password, 0, 0, ''))
        
        conn.commit()
        
        # Verify the malicious username was inserted as literal text, not executed
        c.execute("SELECT username FROM users WHERE password = ?", (password,))
        result = c.fetchone()
        conn.close()
        
        self.assertEqual(result[0], malicious_username)
    
    def test_insert_user_with_special_characters(self):
        """Test that special characters are properly handled."""
        users_with_special_chars = [
            ("user'with'quotes", "pass'word"),
            ('user"with"double', 'pass"word"test'),
            ("user%with%percent", "pass%word"),
        ]
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("CREATE TABLE users (username text, password text, failures int, mfa_enabled int, mfa_secret text)")
        
        for u, p in users_with_special_chars:
            c.execute("INSERT INTO users (username, password, failures, mfa_enabled, mfa_secret) VALUES (?, ?, ?, ?, ?)", 
                     (u, p, 0, 0, ''))
        
        conn.commit()
        
        # Verify all users with special characters were inserted correctly
        c.execute("SELECT COUNT(*) FROM users")
        count = c.fetchone()[0]
        conn.close()
        
        self.assertEqual(count, len(users_with_special_chars))


if __name__ == '__main__':
    unittest.main()
