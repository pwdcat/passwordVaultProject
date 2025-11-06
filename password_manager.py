import os
import sqlite3
import random
import string
import hashlib
import threading
import time
from datetime import datetime
from typing import Dict
from cryptography.fernet import Fernet
from password_entry import PasswordEntry

class PasswordManager:
    def __init__(self):
        # Core encryption properties
        self.key = None
        self.password_dict = {}
        
        # Security state
        self.is_unlocked = False
        self.master_password_hash = None
        
        # File paths
        self.key_path = "testkey.key"
        self.database_path = "vault.db"
        
        # Auto-lock functionality
        self.auto_lock_minutes = 5
        self.auto_lock_active = False
        self.last_activity_time = None
        self.auto_lock_timer = None
        
        # Check if vault exists
        self.vault_exists = self.check_vault_exists()

    #
    # ENCRYPTION KEY
    #

    def generate_password(self, length=16, use_uppercase=True, use_lowercase=True, use_digits=True, use_special=True):
        characters = ""
        if use_uppercase: characters += string.ascii_uppercase
        if use_lowercase: characters += string.ascii_lowercase
        if use_digits: characters += string.digits
        if use_special: characters += "!@#$%^&*"
        
        if not characters:
            return ""
        
        return ''.join(random.choice(characters) for _ in range(length))

    #
    # DATABASE
    #

    def check_vault_exists(self) -> bool:
        return os.path.exists(self.database_path)
    
    def init_database(self):
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Create passwords table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                strength TEXT,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create vault configuration table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vault_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_master_hash(self):
        # Save master password hash to database
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO vault_config (key, value)
            VALUES ('master_hash', ?)
        ''', (self.master_password_hash,))
        
        conn.commit()
        conn.close()
    
    def load_master_hash(self):
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT value FROM vault_config WHERE key = ?', ('master_hash',))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            self.master_password_hash = result[0]
    
    def load_passwords_from_db(self):
        if not self.is_unlocked:
            return
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM passwords ORDER BY service')
        rows = cursor.fetchall()
        conn.close()
        
        self.password_dict = {}
        for row in rows:
            # Decrypt password
            decrypted_password = Fernet(self.key).decrypt(row[3].encode()).decode()

            # Convert database timestamps to datetime objects
            created_at = None
            last_updated = None
            
            if len(row) > 6 and row[6]:
                try:
                    created_at = datetime.fromisoformat(row[6].replace('Z', '+00:00'))
                except:
                    created_at = None
                    
            if len(row) > 7 and row[7]:
                try:
                    last_updated = datetime.fromisoformat(row[7].replace('Z', '+00:00'))
                except:
                    last_updated = None

            entry = PasswordEntry(
                id=row[0],
                service=row[1],
                username=row[2],
                password=decrypted_password,
                strength=row[4] or "Unknown",
                notes=row[5] or "",
                created_at=created_at,
                last_updated=last_updated
            )
            self.password_dict[row[0]] = entry

    #
    # MASTER PASSWORD
    #

    def setup_master_password(self, password: str) -> Dict:
        if self.vault_exists:
            return {
                'success': False,
                'error': 'Vault already exists'
            }
        
        if len(password) < 6:
            return {
                'success': False,
                'error': 'Master password must be at least 6 characters'
            }
        
        try:
            # Hash the master password
            self.master_password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            # Generate encryption key
            self.key = Fernet.generate_key()
            
            # Initialize database
            self.init_database()
            
            # Save key and hash
            with open(self.key_path, 'wb') as f:
                f.write(self.key)
            self.save_master_hash()
            
            self.vault_exists = True
            
            return {
                'success': True,
                'message': 'Vault created successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to create vault: {str(e)}'
            }
    
    def verify_master_password(self, password: str) -> Dict:
        if not self.vault_exists:
            return {
                'success': False,
                'error': 'No vault found'
            }
        
        try:
            # Load stored hash
            if not self.master_password_hash:
                self.load_master_hash()
            
            # Verify password
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if password_hash == self.master_password_hash:
                # Load encryption key
                with open(self.key_path, 'rb') as f:
                    self.key = f.read()
                self.is_unlocked = True
                
                # Load passwords
                self.load_passwords_from_db()
                
                # Start auto-lock
                if self.auto_lock_active:
                    self._start_auto_lock_timer()
                
                return {
                    'success': True,
                    'message': 'Vault unlocked successfully'
                }
            else:
                return {
                    'success': False,
                    'error': 'Incorrect master password'
                }
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to unlock vault: {str(e)}'
            }
    
    def change_master_password(self, current_password: str, new_password: str) -> Dict:
        # Check
        current_hash = hashlib.sha256(current_password.encode()).hexdigest()
        if current_hash != self.master_password_hash:
            return {'success': False, 'error': 'Current master password is incorrect'}
        if len(new_password) < 6 or current_password == new_password:
            return {'success': False, 'error': 'New password invalid'}

        try:
            with sqlite3.connect(self.database_path) as conn:
                cursor = conn.cursor()

                # Load all passwords and re-encrypt them
                cursor.execute('SELECT id, password FROM passwords')
                passwords = cursor.fetchall()

                new_key = Fernet.generate_key()
                fernet = Fernet(new_key)

                for password_id, encrypted_password in passwords:
                    decrypted = Fernet(self.key).decrypt(encrypted_password.encode()).decode()
                    reencrypted = fernet.encrypt(decrypted.encode()).decode()
                    cursor.execute('UPDATE passwords SET password = ? WHERE id = ?', (reencrypted, password_id))

                # Update master
                new_hash = hashlib.sha256(new_password.encode()).hexdigest()
                cursor.execute('UPDATE vault_config SET value = ? WHERE key = ?', (new_hash, 'master_hash'))
                conn.commit()

            # Update
            self.master_password_hash = new_hash
            self.key = new_key
            with open(self.key_path, 'wb') as f:
                f.write(self.key)

            return {'success': True, 'message': 'Master password changed successfully'}

        except Exception as e:
            return {'success': False, 'error': f'Failed to change master password: {str(e)}'}

    def lock_vault(self) -> Dict:
        self.is_unlocked = False
        self.master_password_hash = None
        self.password_dict = {}
        
        # Stop auto-lock timer
        if self.auto_lock_timer:
            self.auto_lock_timer.cancel()
            self.auto_lock_timer = None
        
        return {
            'success': True,
            'message': 'Vault locked successfully'
        }

    #
    # DATABASE PASSWORD
    #

    def add_password_to_db(self, service: str, username: str, password: str, notes: str = "") -> Dict:
        if not self.is_unlocked:
            return {
                'success': False,
                'error': 'Vault is locked'
            }
        
        try:
            # Encrypt password
            encrypted_password = Fernet(self.key).encrypt(password.encode()).decode()
            
            # Get password strength
            strength = self.check_password_strength(password)
            
            # Save to database
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO passwords (service, username, password, strength, notes)
                VALUES (?, ?, ?, ?, ?)
            ''', (service, username, encrypted_password, strength, notes))
            
            password_id = cursor.lastrowid
            conn.commit()
            conn.close()

            # Create entry and add to memory
            entry = PasswordEntry(
                id=password_id,
                service=service,
                username=username,
                password=password,
                strength=strength,
                notes=notes,
                created_at=datetime.now(),
                last_updated=datetime.now()
            )
            self.password_dict[password_id] = entry
            
            return {
                'success': True,
                'message': 'Password added successfully',
                'id': password_id
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to add password: {str(e)}'
            }
    
    def get_all_passwords(self) -> Dict:
        if not self.is_unlocked:
            return {
                'success': False,
                'error': 'Vault is locked'
            }
        
        passwords = [entry.to_dict() for entry in self.password_dict.values()]
        
        return {
            'success': True,
            'passwords': passwords,
            'count': len(passwords)
        }
    
    def delete_password_from_db(self, password_id: int) -> Dict:
        if not self.is_unlocked:
            return {
                'success': False,
                'error': 'Vault is locked'
            }
        
        try:
            # Delete from database
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM passwords WHERE id = ?', (password_id,))
            
            if cursor.rowcount == 0:
                conn.close()
                return {
                    'success': False,
                    'error': 'Password not found'
                }
            
            conn.commit()
            conn.close()

            if password_id in self.password_dict:
                del self.password_dict[password_id]
            
            return {
                'success': True,
                'message': 'Password deleted successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to delete password: {str(e)}'
            }

    def update_password_to_db(self, password_id: int, service: str, username: str, password: str, notes: str = "") -> Dict:
        # Update an existing password
        if not self.is_unlocked:
            return {
                'success': False,
                'error': 'Vault is locked'
            }
        
        try:
            # Encrypt password
            encrypted_password = Fernet(self.key).encrypt(password.encode()).decode()
            
            # Get password strength
            strength = self.check_password_strength(password)
            
            # Update in database
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE passwords
                SET service = ?, username = ?, password = ?, strength = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (service, username, encrypted_password, strength, notes, password_id))
            
            if cursor.rowcount == 0:
                conn.close()
                return {
                    'success': False,
                    'error': 'Password not found'
                }
            
            conn.commit()
            conn.close()
            
            # Update in memory
            if password_id in self.password_dict:
                self.password_dict[password_id].service = service
                self.password_dict[password_id].username = username
                self.password_dict[password_id].password = password
                self.password_dict[password_id].strength = strength
                self.password_dict[password_id].notes = notes
                self.password_dict[password_id].last_updated = datetime.now()
            
            return {
                'success': True,
                'message': 'Password updated successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to update password: {str(e)}'
            }
    
    def get_password_from_db(self, password_id: int) -> Dict:
        if not self.is_unlocked:
            return {
                'success': False,
                'error': 'Vault is locked'
            }
        
        if password_id not in self.password_dict:
            return {
                'success': False,
                'error': 'Password not found'
            }
        
        entry = self.password_dict[password_id]
        return {
            'success': True,
            'password': entry.to_dict()
        }

    #
    # PASSWORD GENERATION AND STRENGTH
    #

    def check_password_strength(self, password: str) -> str:
        score = 0
        
        # Length check
        if len(password) < 8:
            return "Weak"
        elif len(password) >= 12:
            score += 2
        else:
            score += 1
        
        # Character type checks
        if any(c.isupper() for c in password):
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in "!@#$%^&*" for c in password):
            score += 1
        
        # Determine strength
        if score <= 2:
            return "Weak"
        elif score <= 4:
            return "Medium"
        else:
            return "Strong"
    
    # AUTO-LOCK
    
    def set_auto_lock_minutes(self, minutes: int) -> Dict:
        if minutes < 1:
            return {
                'success': False,
                'error': 'Auto-lock minutes must be at least 1'
            }
        
        self.auto_lock_minutes = minutes
        
        if self.auto_lock_active:
            # Restart timer with new timeout
            if self.auto_lock_timer:
                self.auto_lock_timer.cancel()
            self._start_auto_lock_timer()
        
        return {
            'success': True,
            'message': f'Auto-lock set to {minutes} minutes'
        }
    
    def get_auto_lock_status(self) -> Dict:
        time_remaining = 0
        if self.is_unlocked and self.last_activity_time:
            elapsed = time.time() - self.last_activity_time
            time_remaining = max(0, (self.auto_lock_minutes * 60) - elapsed)
        
        return {
            'success': True,
            'active': self.auto_lock_active,
            'lock_minutes': self.auto_lock_minutes,
            'time_remaining': time_remaining,
            'formatted_time': self._format_time_remaining(time_remaining)
        }
    
    def register_activity(self) -> Dict:
        if self.is_unlocked:
            self.last_activity_time = time.time()
            
            # Restart auto-lock timer
            if self.auto_lock_active and self.auto_lock_timer:
                self.auto_lock_timer.cancel()
                self._start_auto_lock_timer()
        
        return {
            'success': True,
            'message': 'Activity registered'
        }
    
    def _start_auto_lock_timer(self):
        if self.auto_lock_timer:
            self.auto_lock_timer.cancel()
        
        self.last_activity_time = time.time()
        self.auto_lock_timer = threading.Timer(
            self.auto_lock_minutes * 60,
            self._auto_lock
        )
        self.auto_lock_timer.start()
    
    def _auto_lock(self):
        self.lock_vault()
    
    def _format_time_remaining(self, seconds: float) -> str:
        minutes = int(seconds // 60)
        seconds = int(seconds % 60)
        return f"{minutes}:{seconds:02d}"

    #
    # VAULT STATUS
    #

    def get_vault_status(self) -> Dict:
        return {
            'is_unlocked': self.is_unlocked,
            'passwords_count': len(self.password_dict),
            'database_exists': self.vault_exists,
            'auto_lock_active': self.auto_lock_active,
            'auto_lock_minutes': self.auto_lock_minutes
        }
    
    def reset_vault(self) -> Dict:
        try:
            # Remove database file
            if os.path.exists(self.database_path):
                os.remove(self.database_path)
            
            # Remove key file
            if os.path.exists(self.key_path):
                os.remove(self.key_path)
            
            # Reset all state
            self.is_unlocked = False
            self.master_password_hash = None
            self.password_dict = {}
            self.key = None
            self.vault_exists = False
            
            # Stop auto-lock timer
            if self.auto_lock_timer:
                self.auto_lock_timer.cancel()
                self.auto_lock_timer = None
            
            return {
                'success': True,
                'message': 'Vault reset successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to reset vault: {str(e)}'
            }
    
    def export_backup(self, backup_path: str) -> Dict:
        try:
            if not self.vault_exists:
                return {
                    'success': False,
                    'error': 'No vault to backup'
                }
            
            import shutil
            shutil.copy2(self.database_path, backup_path)
            
            return {
                'success': True,
                'message': f'Backup created at {backup_path}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to create backup: {str(e)}'
            }
