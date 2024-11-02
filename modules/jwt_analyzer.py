import jwt
import json
import base64
import requests
import hashlib
from colorama import Fore, Style, init
from alive_progress import alive_bar
import concurrent.futures
from datetime import datetime, timezone

class JWTAnalyzer:
    def __init__(self):
        init(autoreset=True)
        self.common_secrets = [
            "secret",
            "password",
            "key",
            "jwt_secret",
            "jwt_token",
            "api_secret",
            "secret_key",
            "your-256-bit-secret",
            "your-384-bit-secret",
            "your-512-bit-secret",
            "SECRET_KEY",
            "super-secret",
            "auth_secret",
            "authentication_secret",
            "jwt_secret_key",
            "secret123",
            "secretkey",
            "private_key",
            "jwt_private_key",
        ]

    def decode_token_without_verification(self, token):
        """Decode JWT token without verification to analyze its contents"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            header = json.loads(base64.b64decode(self._pad_base64(parts[0])))
            payload = json.loads(base64.b64decode(self._pad_base64(parts[1])))
            
            return {
                'header': header,
                'payload': payload,
                'signature': parts[2]
            }
        except Exception as e:
            print(f"{Fore.RED}Error decoding token: {str(e)}{Style.RESET_ALL}")
            return None

    def _pad_base64(self, data):
        """Pad base64 data if necessary"""
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += '=' * padding
        return data.replace('-', '+').replace('_', '/')

    def check_none_algorithm(self, token):
        """Check if token is vulnerable to 'none' algorithm attack"""
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            header = jwt.get_unverified_header(token)
            
            if header['alg'].lower() == 'none':
                return True, "Token uses 'none' algorithm - vulnerable to signature bypass"
            return False, None
        except Exception:
            return False, None

    def check_weak_secret(self, token):
        """Check if token can be decoded with common weak secrets"""
        vulnerabilities = []
        
        print(f"\n{Fore.CYAN}Testing common weak secrets...{Style.RESET_ALL}")
        with alive_bar(len(self.common_secrets)) as bar:
            for secret in self.common_secrets:
                try:
                    jwt.decode(token, secret, algorithms=['HS256', 'HS384', 'HS512'])
                    vulnerabilities.append(f"Token can be decoded with weak secret: {secret}")
                except jwt.InvalidTokenError:
                    pass
                bar()
        
        return len(vulnerabilities) > 0, vulnerabilities

    def check_expiration(self, token):
        """Check token expiration"""
        try:
            decoded = self.decode_token_without_verification(token)
            if not decoded:
                return False, "Could not decode token"
            
            payload = decoded['payload']
            
            # Check for expiration claim
            if 'exp' not in payload:
                return True, "Token has no expiration claim"
            
            exp_timestamp = payload['exp']
            exp_datetime = datetime.fromtimestamp(exp_timestamp, timezone.utc)
            current_datetime = datetime.now(timezone.utc)
            
            if exp_datetime < current_datetime:
                return True, "Token has expired"
            
            # Check for unreasonably long expiration
            time_diff = exp_datetime - current_datetime
            if time_diff.days > 30:
                return True, f"Token has a long expiration time ({time_diff.days} days)"
            
            return False, None
        except Exception as e:
            return False, f"Error checking expiration: {str(e)}"

    def check_kid_injection(self, token):
        """Check for potential Key ID (kid) header injection vulnerability"""
        try:
            decoded = self.decode_token_without_verification(token)
            if not decoded:
                return False, None
            
            header = decoded['header']
            if 'kid' in header:
                # Check for common SQL injection patterns
                kid_value = header['kid']
                sql_patterns = ["'", "\"", "OR", "AND", "UNION", "--", ";"]
                if any(pattern.lower() in kid_value.lower() for pattern in sql_patterns):
                    return True, "Potential SQL injection in 'kid' header parameter"
                
                # Check for path traversal
                if '../' in kid_value or '..' in kid_value:
                    return True, "Potential path traversal in 'kid' header parameter"
                
                # Check for command injection
                if ';' in kid_value or '|' in kid_value or '>' in kid_value:
                    return True, "Potential command injection in 'kid' header parameter"
                
            return False, None
        except Exception as e:
            return False, f"Error checking kid injection: {str(e)}"

    def analyze_token(self, token):
        """Perform comprehensive analysis of JWT token"""
        print(f"\n{Fore.GREEN}Starting JWT Token Analysis{Style.RESET_ALL}")
        
        # Decode token without verification
        decoded = self.decode_token_without_verification(token)
        if not decoded:
            print(f"{Fore.RED}Invalid JWT token format{Style.RESET_ALL}")
            return
        
        # Print token structure
        print(f"\n{Fore.CYAN}Token Structure:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Header:{Style.RESET_ALL}")
        print(json.dumps(decoded['header'], indent=2))
        print(f"\n{Fore.YELLOW}Payload:{Style.RESET_ALL}")
        print(json.dumps(decoded['payload'], indent=2))
        
        vulnerabilities = []
        
        # Check for 'none' algorithm vulnerability
        none_vuln, none_details = self.check_none_algorithm(token)
        if none_vuln:
            vulnerabilities.append(none_details)
        
        # Check for weak secrets
        weak_secret_vuln, weak_secret_details = self.check_weak_secret(token)
        if weak_secret_vuln:
            vulnerabilities.extend(weak_secret_details)
        
        # Check expiration
        exp_vuln, exp_details = self.check_expiration(token)
        if exp_vuln:
            vulnerabilities.append(exp_details)
        
        # Check for kid injection
        kid_vuln, kid_details = self.check_kid_injection(token)
        if kid_vuln:
            vulnerabilities.append(kid_details)
        
        # Print vulnerabilities
        if vulnerabilities:
            print(f"\n{Fore.RED}Vulnerabilities Found:{Style.RESET_ALL}")
            for vuln in vulnerabilities:
                print(f"- {vuln}")
        else:
            print(f"\n{Fore.GREEN}No common vulnerabilities detected{Style.RESET_ALL}")
        
        # Additional security recommendations
        self.print_security_recommendations(decoded)

    def print_security_recommendations(self, decoded):
        """Print security recommendations based on token analysis"""
        print(f"\n{Fore.CYAN}Security Recommendations:{Style.RESET_ALL}")
        
        # Check algorithm
        if decoded['header'].get('alg') in ['HS256', 'HS384', 'HS512']:
            print("- Consider using RS256 (RSA) instead of HMAC if this is a public application")
        
        # Check claims
        payload = decoded['payload']
        if 'iat' not in payload:
            print("- Add 'iat' (Issued At) claim to the token")
        if 'aud' not in payload:
            print("- Consider adding 'aud' (Audience) claim to restrict token usage")
        if 'jti' not in payload:
            print("- Consider adding 'jti' (JWT ID) claim for token uniqueness")
        
        # General recommendations
        print("- Ensure secret key length matches the hash algorithm length")
        print("- Implement token revocation mechanism")
        print("- Use secure token transmission (HTTPS)")

    def modify_token(self, token):
        """Interactive token modification function"""
        print(f"\n{Fore.CYAN}JWT Token Modifier{Style.RESET_ALL}")
        
        # Decode token without verification
        decoded = self.decode_token_without_verification(token)
        if not decoded:
            print(f"{Fore.RED}Invalid JWT token format{Style.RESET_ALL}")
            return
        
        while True:
            print(f"\n{Fore.YELLOW}Current Token Structure:{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}Header:{Style.RESET_ALL}")
            print(json.dumps(decoded['header'], indent=2))
            print(f"\n{Fore.CYAN}Payload:{Style.RESET_ALL}")
            print(json.dumps(decoded['payload'], indent=2))
            
            print(f"\n{Fore.YELLOW}Modification Options:{Style.RESET_ALL}")
            print("1. Modify Header")
            print("2. Modify Payload")
            print("3. Change Algorithm")
            print("4. Add Custom Claim")
            print("5. Remove Claim")
            print("6. Generate Token")
            print("7. Exit")
            
            choice = input(f"\n{Fore.GREEN}Enter your choice (1-7): {Style.RESET_ALL}")
            
            if choice == '1':
                self._modify_header(decoded)
            elif choice == '2':
                self._modify_payload(decoded)
            elif choice == '3':
                self._change_algorithm(decoded)
            elif choice == '4':
                self._add_claim(decoded)
            elif choice == '5':
                self._remove_claim(decoded)
            elif choice == '6':
                self._generate_modified_token(decoded)
            elif choice == '7':
                break
            else:
                print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

    def _modify_header(self, decoded):
        """Modify header values"""
        print(f"\n{Fore.CYAN}Current Header:{Style.RESET_ALL}")
        print(json.dumps(decoded['header'], indent=2))
        
        key = input(f"\n{Fore.YELLOW}Enter header key to modify: {Style.RESET_ALL}")
        if key in decoded['header']:
            value = input(f"{Fore.YELLOW}Enter new value: {Style.RESET_ALL}")
            decoded['header'][key] = value
            print(f"{Fore.GREEN}Header modified successfully{Style.RESET_ALL}")
        else:
            add = input(f"{Fore.YELLOW}Key doesn't exist. Add it? (y/n): {Style.RESET_ALL}")
            if add.lower() == 'y':
                value = input(f"{Fore.YELLOW}Enter value: {Style.RESET_ALL}")
                decoded['header'][key] = value
                print(f"{Fore.GREEN}Header modified successfully{Style.RESET_ALL}")

    def _modify_payload(self, decoded):
        """Modify payload values"""
        print(f"\n{Fore.CYAN}Current Payload:{Style.RESET_ALL}")
        print(json.dumps(decoded['payload'], indent=2))
        
        key = input(f"\n{Fore.YELLOW}Enter payload key to modify: {Style.RESET_ALL}")
        if key in decoded['payload']:
            value = input(f"{Fore.YELLOW}Enter new value: {Style.RESET_ALL}")
            try:
                # Try to convert to int or float if possible
                if value.isdigit():
                    value = int(value)
                else:
                    try:
                        value = float(value)
                    except ValueError:
                        pass
                decoded['payload'][key] = value
                print(f"{Fore.GREEN}Payload modified successfully{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error modifying payload: {str(e)}{Style.RESET_ALL}")
        else:
            add = input(f"{Fore.YELLOW}Key doesn't exist. Add it? (y/n): {Style.RESET_ALL}")
            if add.lower() == 'y':
                value = input(f"{Fore.YELLOW}Enter value: {Style.RESET_ALL}")
                decoded['payload'][key] = value
                print(f"{Fore.GREEN}Payload modified successfully{Style.RESET_ALL}")

    def _change_algorithm(self, decoded):
        """Change token algorithm"""
        print(f"\n{Fore.CYAN}Available Algorithms:{Style.RESET_ALL}")
        algorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'none']
        
        for i, alg in enumerate(algorithms, 1):
            print(f"{i}. {alg}")
        
        try:
            choice = int(input(f"\n{Fore.YELLOW}Select algorithm (1-{len(algorithms)}): {Style.RESET_ALL}"))
            if 1 <= choice <= len(algorithms):
                decoded['header']['alg'] = algorithms[choice-1]
                print(f"{Fore.GREEN}Algorithm changed successfully{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Invalid input{Style.RESET_ALL}")

    def _add_claim(self, decoded):
        """Add custom claim to payload"""
        print(f"\n{Fore.CYAN}Add Custom Claim{Style.RESET_ALL}")
        
        key = input(f"{Fore.YELLOW}Enter claim key: {Style.RESET_ALL}")
        value = input(f"{Fore.YELLOW}Enter claim value: {Style.RESET_ALL}")
        
        try:
            # Try to convert to int or float if possible
            if value.isdigit():
                value = int(value)
            else:
                try:
                    value = float(value)
                except ValueError:
                    pass
            decoded['payload'][key] = value
            print(f"{Fore.GREEN}Claim added successfully{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error adding claim: {str(e)}{Style.RESET_ALL}")

    def _remove_claim(self, decoded):
        """Remove claim from payload"""
        print(f"\n{Fore.CYAN}Current Claims:{Style.RESET_ALL}")
        for key in decoded['payload'].keys():
            print(f"- {key}")
        
        key = input(f"\n{Fore.YELLOW}Enter claim key to remove: {Style.RESET_ALL}")
        if key in decoded['payload']:
            del decoded['payload'][key]
            print(f"{Fore.GREEN}Claim removed successfully{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Claim not found{Style.RESET_ALL}")

    def _generate_modified_token(self, decoded):
        """Generate modified token"""
        print(f"\n{Fore.CYAN}Generate Modified Token{Style.RESET_ALL}")
        
        algorithm = decoded['header'].get('alg')
        
        if algorithm.lower() == 'none':
            # Generate token without signature
            header_b64 = base64.urlsafe_b64encode(json.dumps(decoded['header']).encode()).rstrip(b'=').decode()
            payload_b64 = base64.urlsafe_b64encode(json.dumps(decoded['payload']).encode()).rstrip(b'=').decode()
            modified_token = f"{header_b64}.{payload_b64}."
        
        elif algorithm.startswith('RS'):
            print(f"{Fore.YELLOW}RSA algorithm detected. You need a private key to sign the token.{Style.RESET_ALL}")
            print("1. Generate new key pair")
            print("2. Use existing private key")
            choice = input(f"{Fore.GREEN}Enter your choice (1-2): {Style.RESET_ALL}")
            
            try:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.hazmat.backends import default_backend
                
                if choice == '1':
                    # Generate new RSA key pair
                    private_key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=2048,
                        backend=default_backend()
                    )
                    
                    # Save private key to file
                    print(f"\n{Fore.YELLOW}Saving private key...{Style.RESET_ALL}")
                    pem = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    with open('private_key.pem', 'wb') as f:
                        f.write(pem)
                    print(f"{Fore.GREEN}Private key saved to private_key.pem{Style.RESET_ALL}")
                    
                    # Save public key to file
                    print(f"\n{Fore.YELLOW}Saving public key...{Style.RESET_ALL}")
                    public_key = private_key.public_key()
                    pem = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    with open('public_key.pem', 'wb') as f:
                        f.write(pem)
                    print(f"{Fore.GREEN}Public key saved to public_key.pem{Style.RESET_ALL}")
                    
                elif choice == '2':
                    # Load existing private key
                    key_path = input(f"{Fore.YELLOW}Enter path to private key file: {Style.RESET_ALL}")
                    with open(key_path, 'rb') as key_file:
                        private_key = serialization.load_pem_private_key(
                            key_file.read(),
                            password=None,
                            backend=default_backend()
                        )
                else:
                    print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")
                    return
                
                # Generate token with RSA private key
                modified_token = jwt.encode(
                    decoded['payload'],
                    private_key,
                    algorithm=algorithm,
                    headers=decoded['header']
                )
                if isinstance(modified_token, bytes):
                    modified_token = modified_token.decode()
                    
            except Exception as e:
                print(f"{Fore.RED}Error generating RSA token: {str(e)}{Style.RESET_ALL}")
                return
        
        else:  # HMAC algorithms (HS256, HS384, HS512)
            secret = input(f"{Fore.YELLOW}Enter secret key for signing: {Style.RESET_ALL}")
            try:
                modified_token = jwt.encode(
                    decoded['payload'],
                    secret,
                    algorithm=algorithm,
                    headers=decoded['header']
                )
                if isinstance(modified_token, bytes):
                    modified_token = modified_token.decode()
            except Exception as e:
                print(f"{Fore.RED}Error generating token: {str(e)}{Style.RESET_ALL}")
                return
        
        print(f"\n{Fore.GREEN}Modified Token:{Style.RESET_ALL}")
        print(modified_token)
        
        save = input(f"\n{Fore.YELLOW}Save token to file? (y/n): {Style.RESET_ALL}")
        if save.lower() == 'y':
            filename = input(f"{Fore.YELLOW}Enter filename: {Style.RESET_ALL}")
            try:
                with open(filename, 'w') as f:
                    f.write(modified_token)
                print(f"{Fore.GREEN}Token saved to {filename}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error saving token: {str(e)}{Style.RESET_ALL}")

def main():
    print(f"""{Fore.CYAN}
    ╔═╗┌─┐┬ ┬╦ ╦┬ ┬┌┐┌┌┬┐  ╔═╗╦ ╦╔╦╗  ╔═╗┌┐┌┌─┐┬ ┬┬─┐┌─┐┬─┐
    ╚═╗├─┘└┬┘╠═╣│ ││││ │   ╠═╝║║║ ║   ╠═╣│││├─┤│ │┌┬┘├┤ ├┬┘
    ╚═╝┴   ┴ ╩ ╩└─┘┘└┘ ┴   ╩  ╚╩╝ ╩   ╩ ╩┘└┘┴ ┴└─┘┴└─└─┘┴└─
    JWT Token Security Analyzer & Modifier
    {Style.RESET_ALL}""")

    while True:
        print(f"\n{Fore.YELLOW}Options:{Style.RESET_ALL}")
        print("1. Analyze Token")
        print("2. Modify Token")
        print("3. Exit")
        
        choice = input(f"\n{Fore.GREEN}Enter your choice (1-3): {Style.RESET_ALL}")
        
        if choice == '1':
            token = input(f"{Fore.YELLOW}Enter JWT token to analyze: {Style.RESET_ALL}")
            analyzer = JWTAnalyzer()
            analyzer.analyze_token(token)
        elif choice == '2':
            token = input(f"{Fore.YELLOW}Enter JWT token to modify: {Style.RESET_ALL}")
            analyzer = JWTAnalyzer()
            analyzer.modify_token(token)
        elif choice == '3':
            break
        else:
            print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

if __name__ == "__main__":
    main()