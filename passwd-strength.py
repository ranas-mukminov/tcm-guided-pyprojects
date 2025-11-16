#!/usr/bin/env python3
"""
Password strength checker.
Validates password against security best practices.
"""
import re


def check_password_strength(password):
    """
    Check password strength against multiple criteria.

    Args:
        password (str): Password to check

    Returns:
        tuple: (is_strong, feedback_list)
    """
    feedback = []
    is_strong = True

    # Check minimum length
    if len(password) < 8:
        feedback.append("Password must be at least 8 characters long")
        is_strong = False

    # Check for uppercase letters
    if not re.search(r'[A-Z]', password):
        feedback.append("Password should contain at least one uppercase letter")
        is_strong = False

    # Check for lowercase letters
    if not re.search(r'[a-z]', password):
        feedback.append("Password should contain at least one lowercase letter")
        is_strong = False

    # Check for digits
    if not re.search(r'\d', password):
        feedback.append("Password should contain at least one digit")
        is_strong = False

    # Check for special characters
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        feedback.append("Password should contain at least one special character (!@#$%^&* etc.)")
        is_strong = False

    # Check for common patterns
    common_patterns = ['password', '12345', 'qwerty', 'admin', 'letmein']
    if any(pattern in password.lower() for pattern in common_patterns):
        feedback.append("Password contains a common pattern - avoid dictionary words and sequences")
        is_strong = False

    # Check for repeated characters (3+ in a row)
    if re.search(r'(.)\1{2,}', password):
        feedback.append("Password contains too many repeated characters")
        is_strong = False

    return is_strong, feedback


def main():
    """Main function to run password strength checker."""
    print("--- Password Strength Checker ---")
    passwd = input("Enter your password: ")

    is_strong, feedback = check_password_strength(passwd)

    if is_strong:
        print("\n✓ Password is strong!")
        print("Your password meets all security requirements.")
    else:
        print("\n✗ Password is weak!")
        print("\nIssues found:")
        for i, issue in enumerate(feedback, 1):
            print(f"  {i}. {issue}")

        print("\nRecommendations:")
        print("  • Use a mix of uppercase and lowercase letters")
        print("  • Include numbers and special characters")
        print("  • Avoid common words and patterns")
        print("  • Make it at least 12 characters for better security")


if __name__ == "__main__":
    main()
