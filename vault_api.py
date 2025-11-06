from password_manager import PasswordManager

_vault_instance = None

def initialize_vault():
    global _vault_instance
    _vault_instance = PasswordManager()
    return _vault_instance

def get_vault_instance():
    global _vault_instance
    if _vault_instance is None:
        _vault_instance = PasswordManager()
    return _vault_instance

#
# AUTHENTICATION
#

def setup_master_password(password):
    # Setup master password for first time
    return get_vault_instance().setup_master_password(password)

def verify_master_password(password):
    return get_vault_instance().verify_master_password(password)

def lock_vault():
    return get_vault_instance().lock_vault()

#
# PASSWORD MANAGEMENT
#

def get_all_passwords():
    return get_vault_instance().get_all_passwords()

def add_password(service, username, password, notes=""):
    return get_vault_instance().add_password_to_db(service, username, password, notes)

def update_password(password_id, service, username, password, notes=""):
    return get_vault_instance().update_password_to_db(password_id, service, username, password, notes)

def delete_password(password_id):
    return get_vault_instance().delete_password_from_db(password_id)

def get_password(password_id):
    return get_vault_instance().get_password_from_db(password_id)

#
# PASSWORD GENERATION
#

def generate_password(**kwargs):
    password = get_vault_instance().generate_password(**kwargs)
    return {
        'success': True,
        'password': password
    }

def get_password_suggestions():
    return {
        'success': True,
        'suggestions': [
            'Use at least 12 characters',
            'Include uppercase and lowercase letters',
            'Include numbers and special characters',
            'Avoid common words or patterns',
            'Use different passwords for each service'
        ]
    }

#
# PASSWORD STRENGTH
#

def check_password_strength(password):
    strength = get_vault_instance().check_password_strength(password)
    return {
        'success': True,
        'strength': strength,
        'color': '#888888' if strength == 'Medium' else '#dc3545' if strength == 'Weak' else '#28a745'
    }

#
# AUTO-LOCK
#

def set_auto_lock_minutes(minutes):
    return get_vault_instance().set_auto_lock_minutes(minutes)

def get_auto_lock_status():
    return get_vault_instance().get_auto_lock_status()

def register_activity():
    return get_vault_instance().register_activity()

#
# MISC
#

def get_vault_status():
    return get_vault_instance().get_vault_status()

def export_backup(backup_path):
    return get_vault_instance().export_backup(backup_path)

def reset_vault():
    return get_vault_instance().reset_vault()

def change_master_password(current_password, new_password):
    return get_vault_instance().change_master_password(current_password, new_password)

#
# HELPERS
#

def is_vault_unlocked():
    status = get_vault_status()
    return status.get('is_unlocked', False)

def get_password_count():
    if not is_vault_unlocked():
        return 0
    passwords = get_all_passwords()
    return passwords.get('count', 0) if passwords.get('success') else 0

def generate_strong_password():
    password = get_vault_instance().generate_password(
        length=16,
        use_lowercase=True,
        use_uppercase=True,
        use_digits=True,
        use_special=True
    )
    return password

def check_strength(password):
    result = check_password_strength(password)
    if result.get('success'):
        return {
            'strength': result['strength'],
            'color': result.get('color', '#888888'),
            'score': result.get('details', {}).get('score', 0),
            'issues': result.get('details', {}).get('issues', []),
            'suggestions': result.get('details', {}).get('suggestions', [])
        }
    return None

# FRONTEND INTEGRATION

def format_password_for_display(password_data):
    if not password_data:
        return None
    
    return {
        'id': password_data.get('id'),
        'service': password_data.get('service', ''),
        'username': password_data.get('username', ''),
        'password': password_data.get('password', ''),
        'strength': password_data.get('strength', 'Unknown'),
        'notes': password_data.get('notes', ''),
        'last_updated': password_data.get('last_updated', ''),
        'created_at': password_data.get('created_at', '')
    }

def prepare_password_list(passwords_result):
    if not passwords_result.get('success'):
        return []
    
    formatted_passwords = []
    for password_data in passwords_result.get('passwords', []):
        formatted_passwords.append(format_password_for_display(password_data))
    
    return formatted_passwords

def get_session_info():
    status = get_vault_status()
    auto_lock = get_auto_lock_status()
    
    return {
        'vault_unlocked': status.get('is_unlocked', False),
        'password_count': status.get('passwords_count', 0),
        'auto_lock_active': auto_lock.get('active', False),
        'auto_lock_minutes': auto_lock.get('lock_minutes', 5),
        'time_remaining': auto_lock.get('formatted_time', '0:00')
    }

# Initialize the vault when module is imported
initialize_vault()
