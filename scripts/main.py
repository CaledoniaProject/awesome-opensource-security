#!/usr/bin/env python3.10
"""
Lists Manager - Update and dump data from markdown files

Dependencies:
- requests: For HTTP requests
- beautifulsoup4: For HTML parsing
- PyPDF2: For PDF title extraction (optional, install with: pip install PyPDF2)

Features:
- GitHub repository processing
- GitHub Gist processing  
- PDF title extraction (downloads and parses PDFs)
- General web page metadata extraction
- SQLite database storage with update optimization
"""

import os
import re
import json
import sys
import argparse
import sqlite3
import requests
import tempfile
import urllib3
from datetime import datetime, timedelta
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import PyPDF2

# Configuration: Whitelist domains that should skip processing and use pre-extracted titles
WHITELIST_DOMAINS = [
    'paper.seebug.org',
    'zhuanlan.zhihu.com',
    'bbs.kanxue.com'
]


class DatabaseManager:
    """Manages SQLite database operations for the lists project."""
    
    def __init__(self, db_path="data.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database with the required table structure."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                title TEXT,
                description TEXT,
                categories TEXT,
                stars INTEGER DEFAULT 0,
                repo_updated_at INTEGER,
                repo_pushed_at INTEGER,
                updated_at INTEGER DEFAULT (strftime('%s', 'now')),
                status INTEGER DEFAULT 0,
                error TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def insert_or_update(self, url, title=None, description=None, categories=None, stars=0, 
                        repo_updated_at=None, repo_pushed_at=None, status=0, error=None):
        """Insert or update a record in the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Trim whitespace from title and description
        title = title.strip() if title else None
        description = description.strip() if description else None
        
        # Truncate description to no more than 400 characters
        if description and len(description) > 400:
            description = description[:400].rstrip() + '...'
        
        categories_json = json.dumps(categories) if categories else None
        
        # Convert ISO datetime strings to Unix timestamps
        repo_updated_timestamp = self._iso_to_timestamp(repo_updated_at)
        repo_pushed_timestamp = self._iso_to_timestamp(repo_pushed_at)
        
        cursor.execute("""
            INSERT OR REPLACE INTO data 
            (url, title, description, categories, stars, repo_updated_at, repo_pushed_at, status, error, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%s', 'now'))
        """, (url, title, description, categories_json, stars, repo_updated_timestamp, repo_pushed_timestamp, status, error))
        
        conn.commit()
        conn.close()
    
    def _iso_to_timestamp(self, iso_string):
        """Convert ISO datetime string to Unix timestamp."""
        if not iso_string:
            return None
        try:
            # Handle both with and without 'Z' suffix
            iso_string = iso_string.replace('Z', '+00:00')
            dt = datetime.fromisoformat(iso_string)
            return int(dt.timestamp())
        except (ValueError, TypeError):
            return None
    
    def get_existing_entry(self, url):
        """Get existing entry for a URL."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM data WHERE url = ?", (url,))
        row = cursor.fetchone()
        
        conn.close()
        return dict(row) if row else None
    
    def should_update_entry(self, existing_entry, new_status, force_update=False):
        """Determine if an entry should be updated based on age and status."""
        if not existing_entry:
            return True  # New entry, always insert
        
        # Always retry failed entries
        if new_status == 0:
            return True
        
        # Force update if -a flag is used
        if force_update:
            return True
        
        # For successful entries, only update if older than 1 month
        if new_status == 1 and existing_entry['status'] == 1:
            try:
                # Use updated_at field (now an integer timestamp)
                updated_at_timestamp = existing_entry['updated_at']
                if updated_at_timestamp:
                    updated_at = datetime.fromtimestamp(updated_at_timestamp)
                    one_month_ago = datetime.now() - timedelta(days=30)
                    return updated_at < one_month_ago
                else:
                    # If no timestamp, update it
                    return True
            except (ValueError, TypeError):
                # If we can't parse the timestamp, update it
                return True
        
        # If existing entry was failed and new one is successful, always update
        if existing_entry['status'] == 0 and new_status == 1:
            return True
        
        return False
    
    def get_all_data(self):
        """Retrieve all data from the database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM data ORDER BY id")
        rows = cursor.fetchall()
        
        conn.close()
        return [dict(row) for row in rows]
    
    def get_failed_entries(self):
        """Retrieve only failed entries (status = 0) from the database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM data WHERE status = 0 ORDER BY id")
        rows = cursor.fetchall()
        
        conn.close()
        return [dict(row) for row in rows]
    
    def delete_failed_entries(self):
        """Delete all failed entries (status = 0) from the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # First count how many failed entries exist
        cursor.execute("SELECT COUNT(*) FROM data WHERE status = 0")
        count = cursor.fetchone()[0]
        
        if count == 0:
            conn.close()
            return 0
        
        # Delete failed entries
        cursor.execute("DELETE FROM data WHERE status = 0")
        conn.commit()
        conn.close()
        
        return count


class MarkdownParser:
    """Parses markdown files and extracts URLs with categories."""
    
    def __init__(self, base_path):
        self.base_path = base_path
    
    def remove_duplicates(self, seq):
        """Remove duplicate items while preserving order."""
        seen = set()
        result = []
        for item in seq:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result
    
    def parse_files(self):
        """Parse all .md files in the parent directory, excluding specified files."""
        results = []
        excluded_files = {'Readme.md', 'Blog.md', 'Payloads.md', 'Bug-Bounty.md'}
        
        for root, _, files in os.walk(self.base_path):
            # Get categories from directory structure
            categories = os.path.relpath(root, self.base_path).split(os.sep)
            if categories == ['.']:
                categories = []
            
            # Clean up category names
            for i in range(len(categories)):
                categories[i] = categories[i].replace('-', ' ')
            
            for file in files:
                if not file.endswith('.md') or file in excluded_files:
                    continue
                
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        current_category = "Uncategorized"
                        
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            
                            # Check if line starts with a letter (category header)
                            if line and line[0].isalpha():
                                current_category = line
                                continue
                            
                            # Look for Seebug URLs in markdown link format first
                            seebug_pattern = r'\[([^\]]*seebug[^\]]*)\]\((https://paper\.seebug\.org/\d+/)\)'
                            seebug_matches = re.findall(seebug_pattern, line, re.IGNORECASE)
                            for title_text, url in seebug_matches:
                                # Clean up URL (remove trailing punctuation)
                                url = re.sub(r'[.,;:!?]+$', '', url)
                                
                                # Extract title from the markdown link text
                                # Remove "seebug:" prefix if present and clean up
                                title = title_text.strip()
                                if title.lower().startswith('seebug:'):
                                    title = title[7:].strip()
                                
                                # Create full categories list
                                full_categories = self.remove_duplicates(
                                    categories + [file.replace('.md', '').replace('-', ' '), current_category]
                                )
                                
                                # Use categories as-is (no normalization)
                                normalized_categories = full_categories
                                
                                results.append({
                                    'url': url,
                                    'categories': normalized_categories,
                                    'title': title  # Pre-extracted title for Seebug URLs
                                })
                            
                            # Look for other URLs in the line (excluding those already processed as Seebug)
                            url_matches = re.findall(r'https?://[^\s\)]+', line)
                            for url in url_matches:
                                # Skip if this URL was already processed as a whitelisted domain
                                if any(domain in url for domain in WHITELIST_DOMAINS):
                                    continue
                                    
                                # Clean up URL (remove trailing punctuation)
                                url = re.sub(r'[.,;:!?]+$', '', url)
                                
                                # Create full categories list
                                full_categories = self.remove_duplicates(
                                    categories + [file.replace('.md', '').replace('-', ' '), current_category]
                                )
                                
                                # Use categories as-is (no normalization)
                                normalized_categories = full_categories
                                
                                results.append({
                                    'url': url,
                                    'categories': normalized_categories
                                })
                
                except Exception as e:
                    print(f"Error parsing {filepath}: {e}")
        
        return results


class URLProcessor:
    """Processes different types of URLs and extracts metadata."""
    
    def __init__(self, github_token=None, proxy=None):
        self.github_token = github_token
        self.proxy = proxy
        
        # Create separate sessions for different purposes
        self.github_session = requests.Session()
        self.general_session = requests.Session()
        
        # Configure both sessions with common settings
        for session in [self.github_session, self.general_session]:
            # Disable SSL verification to ignore SSL errors
            session.verify = False
            
            # Set Windows user agent header
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
            })
            
            # Configure proxy if provided
            if proxy:
                session.proxies = {
                    'http': proxy,
                    'https': proxy
                }
        
        # Only add GitHub token to the GitHub session
        if github_token:
            self.github_session.headers.update({
                'Authorization': f'token {github_token}',
                'Accept': 'application/vnd.github.v3+json'
            })
    
    def process_gist_url(self, url):
        """Process GitHub Gist URLs."""
        gist_id = url.split('/')[-1]
        try:
            response = self.github_session.get(f'https://api.github.com/gists/{gist_id}')
            
            if response.status_code != 200:
                return {
                    'title': f"unknown/{gist_id}",
                    'description': '',
                    'stars': 0,
                    'repo_updated_at': None,
                    'repo_pushed_at': None,
                    'status': 0,
                    'error': f"HTTP {response.status_code}: {gist_id}"
                }
            
            data = response.json()
            
            # Extract username from the gist data
            username = data.get('owner', {}).get('login', 'unknown')
            
            return {
                'title': f"{username}/{gist_id}",
                'description': data.get('description', ''),
                'stars': 0,  # Gists don't have stars
                'repo_updated_at': data.get('updated_at'),
                'repo_pushed_at': data.get('updated_at'),
                'status': 1,
                'error': None
            }
        except requests.exceptions.RequestException as e:
            return {
                'title': f"unknown/{gist_id}",
                'description': '',
                'stars': 0,
                'repo_updated_at': None,
                'repo_pushed_at': None,
                'status': 0,
                'error': f"Request error: {str(e)}"
            }
        except Exception as e:
            return {
                'title': f"unknown/{gist_id}",
                'description': '',
                'stars': 0,
                'repo_updated_at': None,
                'repo_pushed_at': None,
                'status': 0,
                'error': f"Unexpected error: {str(e)}"
            }
    
    def process_github_url(self, url):
        """Process GitHub repository URLs, user/organization URLs, and other GitHub URLs."""
        # Extract owner and repo from URL
        repo_pattern = r'https://github\.com/([^/]+)/([^/]+)'
        user_pattern = r'https://github\.com/([^/]+)/?$'
        
        repo_match = re.match(repo_pattern, url)
        user_match = re.match(user_pattern, url)
        
        if repo_match:
            # This is a repository URL
            owner, repo = repo_match.groups()
            
            try:
                response = self.github_session.get(f'https://api.github.com/repos/{owner}/{repo}')
                
                if response.status_code != 200:
                    return {
                        'title': f"{owner}/{repo}",
                        'description': '',
                        'stars': 0,
                        'repo_updated_at': None,
                        'repo_pushed_at': None,
                        'status': 0,
                        'error': f"HTTP {response.status_code}: {owner}/{repo}"
                    }
                
                data = response.json()
                
                return {
                    'title': f"{owner}/{repo}",
                    'description': data.get('description', ''),
                    'stars': data.get('stargazers_count', 0),
                    'repo_updated_at': data.get('updated_at'),
                    'repo_pushed_at': data.get('pushed_at'),
                    'status': 1,
                    'error': None
                }
            except requests.exceptions.RequestException as e:
                return {
                    'title': f"{owner}/{repo}",
                    'description': '',
                    'stars': 0,
                    'repo_updated_at': None,
                    'repo_pushed_at': None,
                    'status': 0,
                    'error': f"Request error: {str(e)}"
                }
            except Exception as e:
                return {
                    'title': f"{owner}/{repo}",
                    'description': '',
                    'stars': 0,
                    'repo_updated_at': None,
                    'repo_pushed_at': None,
                    'status': 0,
                    'error': f"Unexpected error: {str(e)}"
                }
        
        elif user_match:
            # This is a user/organization URL
            username = user_match.group(1)
            
            try:
                response = self.github_session.get(f'https://api.github.com/users/{username}')
                
                if response.status_code != 200:
                    return {
                        'title': username,
                        'description': '',
                        'stars': 0,
                        'repo_updated_at': None,
                        'repo_pushed_at': None,
                        'status': 0,
                        'error': f"HTTP {response.status_code}: {username}"
                    }
                
                data = response.json()
                
                # Use display name if available, otherwise use username
                display_name = data.get('name') or data.get('login', username)
                title = f"{display_name} (@{username})" if data.get('name') else username
                
                return {
                    'title': title,
                    'description': data.get('bio', ''),
                    'stars': 0,  # Users don't have stars
                    'repo_updated_at': data.get('updated_at'),
                    'repo_pushed_at': data.get('updated_at'),
                    'status': 1,
                    'error': None
                }
            except requests.exceptions.RequestException as e:
                return {
                    'title': username,
                    'description': '',
                    'stars': 0,
                    'repo_updated_at': None,
                    'repo_pushed_at': None,
                    'status': 0,
                    'error': f"Request error: {str(e)}"
                }
            except Exception as e:
                return {
                    'title': username,
                    'description': '',
                    'stars': 0,
                    'repo_updated_at': None,
                    'repo_pushed_at': None,
                    'status': 0,
                    'error': f"Unexpected error: {str(e)}"
                }
        
        else:
            # This is another GitHub URL (docs, help, etc.) - treat as normal URL
            return self.process_other_url(url)
    
    def process_gitlab_url(self, url):
        """Process GitLab repository URLs."""
        # Extract namespace and project from URL
        # Pattern: https://gitlab.com/namespace/project
        pattern = r'https://gitlab\.com/([^/]+)/([^/]+)'
        match = re.match(pattern, url)
        if not match:
            return {
                'title': urlparse(url).netloc,
                'stars': 0,
                'repo_updated_at': None,
                'repo_pushed_at': None,
                'status': 0,
                'error': f"Invalid GitLab URL format: {url}"
            }
        
        namespace, project = match.groups()
        project_path = f"{namespace}/{project}"
        
        try:
            # GitLab API endpoint for projects
            response = self.general_session.get(f'https://gitlab.com/api/v4/projects/{project_path.replace("/", "%2F")}')
            
            if response.status_code != 200:
                return {
                    'title': project_path,
                    'stars': 0,
                    'repo_updated_at': None,
                    'repo_pushed_at': None,
                    'status': 0,
                    'error': f"HTTP {response.status_code}: {project_path}"
                }
            
            data = response.json()
            
            return {
                'title': f"{namespace}/{project}",
                'description': data.get('description', ''),
                'stars': data.get('star_count', 0),
                'repo_updated_at': data.get('last_activity_at'),
                'repo_pushed_at': data.get('last_activity_at'),
                'status': 1,
                'error': None
            }
        except requests.exceptions.RequestException as e:
            return {
                'title': project_path,
                'stars': 0,
                'repo_updated_at': None,
                'repo_pushed_at': None,
                'status': 0,
                'error': f"Request error: {str(e)}"
            }
        except Exception as e:
            return {
                'title': project_path,
                'stars': 0,
                'repo_updated_at': None,
                'repo_pushed_at': None,
                'status': 0,
                'error': f"Unexpected error: {str(e)}"
            }
    
    def process_crates_url(self, url):
        """Process Crates.io URLs."""
        # Extract crate name from URL
        # Pattern: https://crates.io/crates/crate-name
        pattern = r'https://crates\.io/crates/([^/]+)'
        match = re.match(pattern, url)
        if not match:
            return {
                'title': urlparse(url).netloc,
                'stars': 0,
                'repo_updated_at': None,
                'repo_pushed_at': None,
                'status': 0,
                'error': f"Invalid Crates.io URL format: {url}"
            }
        
        crate_name = match.group(1)
        
        try:
            # Crates.io API endpoint
            response = self.general_session.get(f'https://crates.io/api/v1/crates/{crate_name}')
            
            if response.status_code != 200:
                return {
                    'title': crate_name,
                    'stars': 0,
                    'repo_updated_at': None,
                    'repo_pushed_at': None,
                    'status': 0,
                    'error': f"HTTP {response.status_code}: {crate_name}"
                }
            
            data = response.json()
            crate_info = data.get('crate', {})
            
            return {
                'title': f"{crate_info.get('name', crate_name)} v{crate_info.get('max_version', 'unknown')}",
                'description': crate_info.get('description', ''),
                'stars': 0,  # Crates don't have stars, but we could use downloads
                'repo_updated_at': crate_info.get('updated_at'),
                'repo_pushed_at': crate_info.get('updated_at'),
                'status': 1,
                'error': None
            }
        except requests.exceptions.RequestException as e:
            return {
                'title': crate_name,
                'stars': 0,
                'repo_updated_at': None,
                'repo_pushed_at': None,
                'status': 0,
                'error': f"Request error: {str(e)}"
            }
        except Exception as e:
            return {
                'title': crate_name,
                'stars': 0,
                'repo_updated_at': None,
                'repo_pushed_at': None,
                'status': 0,
                'error': f"Unexpected error: {str(e)}"
            }
    
    def process_gitee_url(self, url):
        """Process Gitee repository URLs."""
        # Extract owner and repo from URL
        # Pattern: https://gitee.com/owner/repo
        pattern = r'https://gitee\.com/([^/]+)/([^/]+)'
        match = re.match(pattern, url)
        if not match:
            return {
                'title': urlparse(url).netloc,
                'stars': 0,
                'repo_updated_at': None,
                'repo_pushed_at': None,
                'status': 0,
                'error': f"Invalid Gitee URL format: {url}"
            }
        
        owner, repo = match.groups()
        project_path = f"{owner}/{repo}"
        
        try:
            # Create a separate session for Gitee API with appropriate headers
            gitee_session = requests.Session()
            gitee_session.verify = False  # Disable SSL verification
            
            # Set appropriate headers for Gitee API
            gitee_session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
            })
            
            # Configure proxy if provided
            if self.proxy:
                gitee_session.proxies = {
                    'http': self.proxy,
                    'https': self.proxy
                }
            
            # Gitee API endpoint for projects
            response = gitee_session.get(f'https://gitee.com/api/v5/repos/{owner}/{repo}')
            
            if response.status_code != 200:
                return {
                    'title': project_path,
                    'stars': 0,
                    'repo_updated_at': None,
                    'repo_pushed_at': None,
                    'status': 0,
                    'error': f"HTTP {response.status_code}: {project_path}"
                }
            
            data = response.json()
            
            return {
                'title': f"{owner}/{repo}",
                'description': data.get('description', ''),
                'stars': data.get('stargazers_count', 0),
                'repo_updated_at': data.get('updated_at'),
                'repo_pushed_at': data.get('pushed_at'),
                'status': 1,
                'error': None
            }
        except requests.exceptions.RequestException as e:
            return {
                'title': project_path,
                'stars': 0,
                'repo_updated_at': None,
                'repo_pushed_at': None,
                'status': 0,
                'error': f"Request error: {str(e)}"
            }
        except Exception as e:
            return {
                'title': project_path,
                'stars': 0,
                'repo_updated_at': None,
                'repo_pushed_at': None,
                'status': 0,
                'error': f"Unexpected error: {str(e)}"
            }
    
    def process_pdf_url(self, url):        
        try:
            # Download the PDF
            response = self.general_session.get(url, timeout=30)
            
            if response.status_code != 200:
                return {
                    'title': urlparse(url).netloc,
                    'stars': 0,
                    'repo_updated_at': None,
                    'repo_pushed_at': None,
                    'status': 0,
                    'error': f"HTTP {response.status_code}: {url}"
                }
            
            # Check if it's actually a PDF
            content_type = response.headers.get('content-type', '').lower()
            if 'pdf' not in content_type and not url.lower().endswith('.pdf'):
                return {
                    'title': urlparse(url).netloc,
                    'stars': 0,
                    'repo_updated_at': None,
                    'repo_pushed_at': None,
                    'status': 0,
                    'error': f"Not a PDF file: {content_type}"
                }
            
            # Save PDF to temporary file
            with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_file:
                temp_file.write(response.content)
                temp_file_path = temp_file.name
            
            try:
                # Extract title from PDF
                with open(temp_file_path, 'rb') as pdf_file:
                    pdf_reader = PyPDF2.PdfReader(pdf_file)
                    
                    # Try to get title from metadata first
                    title = None
                    if pdf_reader.metadata and pdf_reader.metadata.title:
                        title = pdf_reader.metadata.title.strip()
                    
                    # If no metadata title, try to extract from first page
                    if not title and len(pdf_reader.pages) > 0:
                        first_page = pdf_reader.pages[0]
                        text = first_page.extract_text()
                        
                        # Look for title-like text (first few lines, capitalized)
                        lines = text.split('\n')
                        for line in lines[:5]:  # Check first 5 lines
                            line = line.strip()
                            if line and len(line) > 5 and len(line) < 200:
                                # Check if it looks like a title (starts with capital, reasonable length)
                                if line[0].isupper() and not line.isupper():
                                    title = line
                                    break
                    
                    # Fallback to filename or domain
                    if not title:
                        parsed_url = urlparse(url)
                        filename = os.path.basename(parsed_url.path)
                        if filename and filename != '/':
                            title = filename.replace('.pdf', '')
                        else:
                            title = parsed_url.netloc
                
                # Extract description from PDF metadata
                description = ""
                if pdf_reader.metadata and pdf_reader.metadata.subject:
                    description = pdf_reader.metadata.subject.strip()
                
                return {
                    'title': title,
                    'description': description,
                    'stars': 0,
                    'repo_updated_at': None,
                    'repo_pushed_at': None,
                    'status': 1,
                    'error': None
                }
            
            finally:
                # Clean up temporary file
                try:
                    os.unlink(temp_file_path)
                except OSError:
                    pass
                    
        except requests.exceptions.RequestException as e:
            return {
                'title': urlparse(url).netloc,
                'stars': 0,
                'repo_updated_at': None,
                'repo_pushed_at': None,
                'status': 0,
                'error': f"Request error: {str(e)}"
            }
        except Exception as e:
            return {
                'title': urlparse(url).netloc,
                'stars': 0,
                'repo_updated_at': None,
                'repo_pushed_at': None,
                'status': 0,
                'error': f"PDF processing error: {str(e)}"
            }
    
    def process_other_url(self, url):
        """Process other URLs by fetching metadata."""
        try:
            response = self.general_session.get(url, timeout=30)

            if response.status_code != 200:
                return {
                    'title': urlparse(url).netloc,
                    'stars': 0,
                    'repo_updated_at': None,
                    'repo_pushed_at': None,
                    'status': 0,
                    'error': f"HTTP {response.status_code}: {url} ({response.text[:200]}{'...' if len(response.text) > 200 else ''})"
                }
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Try to get title from meta tags first
            title = None
            meta_title = soup.find('meta', property='og:title')
            if meta_title:
                title = meta_title.get('content')
            else:
                meta_title = soup.find('meta', attrs={'name': 'title'})
                if meta_title:
                    title = meta_title.get('content')
                else:
                    # Fall back to page title
                    title_tag = soup.find('title')
                    if title_tag:
                        title = title_tag.get_text().strip()
            
            if not title:
                # Use domain name as fallback
                parsed_url = urlparse(url)
                title = parsed_url.netloc
            
            # Try to get description from meta tags
            description = ""
            meta_desc = soup.find('meta', property='og:description')
            if meta_desc:
                description = meta_desc.get('content', '')
            else:
                meta_desc = soup.find('meta', attrs={'name': 'description'})
                if meta_desc:
                    description = meta_desc.get('content', '')
            
            return {
                'title': title,
                'description': description,
                'stars': 0,
                'repo_updated_at': None,
                'repo_pushed_at': None,
                'status': 1,
                'error': None
            }
        except requests.exceptions.RequestException as e:
            return {
                'title': urlparse(url).netloc,
                'stars': 0,
                'repo_updated_at': None,
                'repo_pushed_at': None,
                'status': 0,
                'error': f"Request error: {str(e)}"
            }
        except Exception as e:
            return {
                'title': urlparse(url).netloc,
                'stars': 0,
                'repo_updated_at': None,
                'repo_pushed_at': None,
                'status': 0,
                'error': f"Unexpected error: {str(e)}"
            }
    
    def process_url(self, url, title=None):
        """Process a URL and return metadata based on URL type."""
        # If title is already provided (e.g., from whitelisted domains), use it directly
        if title and any(domain in url for domain in WHITELIST_DOMAINS):
            return {
                'title': title,
                'stars': 0,
                'repo_updated_at': None,
                'repo_pushed_at': None,
                'status': 1,
                'error': None
            }
        
        if 'gist.github.com' in url:
            return self.process_gist_url(url)
        elif 'github.com' in url:
            return self.process_github_url(url)
        elif 'gitlab.com' in url:
            return self.process_gitlab_url(url)
        elif 'gitee.com' in url:
            return self.process_gitee_url(url)
        elif 'crates.io' in url:
            return self.process_crates_url(url)
        elif url.lower().endswith('.pdf'):
            return self.process_pdf_url(url)
        else:
            return self.process_other_url(url)


class ListsManager:
    """Main class that orchestrates the entire process."""
    
    def __init__(self, github_token=None, proxy=None):
        # Get the script directory and parent directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(script_dir)
        
        # Initialize database with path relative to script location
        db_path = os.path.join(script_dir, "data.db")
        self.db_manager = DatabaseManager(db_path)
        self.parser = MarkdownParser(parent_dir)
        self.url_processor = URLProcessor(github_token, proxy)
    
    def _normalize_url(self, url):
        """Normalize URL by removing trailing slash (except for root path)."""
        if not url:
            return url
        # Remove trailing slash, but keep it for root paths (e.g., https://example.com/)
        parsed = urlparse(url)
        if parsed.path and parsed.path != '/' and url.endswith('/'):
            return url.rstrip('/')
        return url
    
    def update_database(self, force_update=False):
        """Update the local SQLite database with data from markdown files."""
        print("Parsing markdown files...")
        parsed_data = self.parser.parse_files()
        
        print(f"Found {len(parsed_data)} URLs to process")
        
        skipped_count = 0
        updated_count = 0
        
        for i, item in enumerate(parsed_data, 1):
            url = item['url']
            categories = item['categories']
            
            # Check if entry exists and should be updated
            existing_entry = self.db_manager.get_existing_entry(url)
            
            # Check if we should update this entry BEFORE making any API requests
            # For existing entries, we need to check if they should be updated based on current status
            should_update = True
            if existing_entry:
                # For existing successful entries, check if they're old enough to update
                if existing_entry['status'] == 1 and not force_update:
                    try:
                        updated_at_timestamp = existing_entry['updated_at']
                        if updated_at_timestamp:
                            updated_at = datetime.fromtimestamp(updated_at_timestamp)
                            one_month_ago = datetime.now() - timedelta(days=30)
                            should_update = updated_at < one_month_ago
                        else:
                            should_update = True
                    except (ValueError, TypeError):
                        should_update = True
                # Always retry failed entries
                elif existing_entry['status'] == 0:
                    should_update = True
            
            if not should_update:
                # print(f"Skipping {i}/{len(parsed_data)}: {url} (recently updated)")
                skipped_count += 1
                continue
            
            print(f"Processing {i}/{len(parsed_data)}: {url}")
            
            # Process the URL to get metadata (only if we're going to update)
            # Pass the title if it was pre-extracted (e.g., for Seebug URLs)
            pre_extracted_title = item.get('title')
            metadata = self.url_processor.process_url(url, pre_extracted_title)
            
            # Print error immediately if processing failed
            if metadata['status'] == 0 and metadata['error']:
                print(f"  ERROR: {metadata['error']}")
            
            # Insert/update in database
            self.db_manager.insert_or_update(
                url=url,
                title=metadata['title'],
                description=metadata.get('description', ''),
                categories=categories,
                stars=metadata['stars'],
                repo_updated_at=metadata['repo_updated_at'],
                repo_pushed_at=metadata['repo_pushed_at'],
                status=metadata['status'],
                error=metadata['error']
            )
            updated_count += 1
        
        print(f"Database update completed! Updated: {updated_count}, Skipped: {skipped_count}")
    
    def dump_data(self):
        """Dump data from the database that exists in markdown files and has succeeded."""
        print("Parsing markdown files to get current URLs...")
        parsed_data = self.parser.parse_files()
        
        # Get all URLs from markdown files
        current_urls = {item['url'] for item in parsed_data}
        
        print(f"Found {len(current_urls)} URLs in markdown files")
        
        # Get all data from database
        all_data = self.db_manager.get_all_data()
        
        # Filter to only include URLs that exist in markdown files and have succeeded
        filtered_data = []
        for item in all_data:
            if item['url'] in current_urls and item['status'] == 1:
                filtered_data.append(item)
        
        print(f"Found {len(filtered_data)} successful entries in database")
        
        # Convert categories back from JSON string to list
        for item in filtered_data:
            if item['categories']:
                try:
                    item['categories'] = json.loads(item['categories'])
                except json.JSONDecodeError:
                    item['categories'] = []
            else:
                item['categories'] = []
        
        print(json.dumps(filtered_data, indent=4, separators=(',', ':'), ensure_ascii=False))
    
    def dump_data_minimized(self):
        """Dump data in JSON format that can be decoded as a list of Go structs."""
        # Parse markdown files to get current URLs and their latest categories
        parsed_data = self.parser.parse_files()
        # Normalize URLs for comparison (remove trailing slashes)
        current_urls = {self._normalize_url(item['url']) for item in parsed_data}
        
        # Create a mapping from normalized URL to latest categories from markdown files
        url_to_categories = {self._normalize_url(item['url']): item['categories'] for item in parsed_data}
        
        # Get all data from database
        all_data = self.db_manager.get_all_data()
        
        # Filter to only include URLs that exist in markdown files and have succeeded
        # Normalize both URLs for comparison
        filtered_data = []
        for item in all_data:
            normalized_db_url = self._normalize_url(item['url'])
            if normalized_db_url in current_urls and item['status'] == 1:
                filtered_data.append(item)
        
        # Build URL to Chinese comment mapping efficiently (scan files once)
        url_to_comment = self._build_url_comment_mapping()
        
        # Build URL to description mapping from markdown files
        url_to_description = self._build_url_description_mapping()
        
        # Build URL to title mapping from markdown files
        url_to_title = self._build_url_title_mapping()
        
        # Convert to Go struct format
        go_structs = []
        for item in filtered_data:
            # Normalize URL for lookup
            normalized_url = self._normalize_url(item['url'])
            # Use latest categories from markdown files instead of database
            categories = url_to_categories.get(normalized_url, [])
            
            # Convert timestamps to ISO format if available
            github_updated_at = None
            if item['repo_updated_at']:
                try:
                    dt = datetime.fromtimestamp(item['repo_updated_at'])
                    github_updated_at = dt.isoformat() + "Z"
                except (ValueError, TypeError):
                    github_updated_at = None
            
            github_pushed_at = None
            if item['repo_pushed_at']:
                try:
                    dt = datetime.fromtimestamp(item['repo_pushed_at'])
                    github_pushed_at = dt.isoformat() + "Z"
                except (ValueError, TypeError):
                    github_pushed_at = None
            
            # Get Chinese comment for this URL (use normalized URL for lookup)
            chinese_comment = url_to_comment.get(normalized_url, "")
            
            # Get description:优先使用markdown里面的，如果没有的话再从sqlite里读取
            description = url_to_description.get(normalized_url, '')
            if not description:
                description = item.get('description', '')
            
            # Get title:优先使用markdown里面的，如果没有的话再从sqlite里读取
            title = url_to_title.get(normalized_url, '')
            if not title:
                title = item.get('title', '')
            
            go_struct = {
                "categories": categories,
                "name": title,
                "description": description,
                "comment": chinese_comment,  # Chinese comment extracted from markdown
                "url": item['url'],
                "githubUpdatedAt": github_updated_at,
                "githubPushedAt": github_pushed_at,
                "githubStar": item['stars']
            }
            go_structs.append(go_struct)
        
        # Output as JSON
        print(json.dumps(go_structs, separators=(',', ':'), ensure_ascii=False))
    
    def _split_by_separator(self, text, maxsplit=-1):
        """
        Split text by various separator patterns: ' - ', '–', '—', ' – ', ' — '
        Returns: (parts, separator_used) tuple
        """
        # Try different separators in order of preference
        separators = [
            ' - ',      # Space-hyphen-space (most common)
            ' – ',      # Space-en-dash-space
            ' — ',      # Space-em-dash-space
        ]
        
        for sep in separators:
            if sep in text:
                if maxsplit == -1:
                    parts = text.split(sep)
                else:
                    parts = text.split(sep, maxsplit)
                return (parts, sep)
        
        # No separator found
        return ([text], None)
    
    def _parse_markdown_link(self, line, url):
        """
        Parse markdown link and extract title, description, and comment based on URL type.
        Returns: (title, description, comment) tuple
        """
        # Parse URL to get host
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        
        # Handle web.archive.org links - extract the original URL from the path
        if host == 'web.archive.org' or host == 'archive.org':
            # web.archive.org URL format: https://web.archive.org/web/TIMESTAMP/ORIGINAL_URL
            # Extract the original URL from the path
            path_parts = parsed_url.path.split('/', 3)  # ['', 'web', 'TIMESTAMP', 'ORIGINAL_URL']
            if len(path_parts) >= 4 and path_parts[1] == 'web':
                original_url = path_parts[3]
                # If original_url already starts with http/https, use it directly
                # Otherwise, prepend the scheme
                if not original_url.startswith('http'):
                    original_url = parsed_url.scheme + '://' + original_url
                # Parse the original URL to get its host
                original_parsed = urlparse(original_url)
                host = original_parsed.netloc
        
        # Pattern to match markdown links: [text](url)
        pattern = r'\[([^\]]+)\]\(([^)]+)\)'
        matches = re.findall(pattern, line)
        
        for link_text, link_url in matches:
            # Clean up URL (remove trailing punctuation)
            clean_link_url = re.sub(r'[.,;:!?]+$', '', link_url)
            if clean_link_url != url:
                continue
            
            # Check URL type by host
            if host == 'gist.github.com':
                # Format: [gist: descr](url) or [gist: descr - comment](url)
                parts, sep = self._split_by_separator(link_text, maxsplit=1)
                if sep and len(parts) == 2:
                    descr = parts[0].replace('gist:', '').strip()
                    potential_comment = parts[1].strip()
                    # Check if potential_comment contains Chinese
                    if self._contains_chinese(potential_comment):
                        # Ensure title has "gist: " prefix
                        title = parts[0].strip()
                        if not title.lower().startswith('gist: '):
                            title = f"gist: {title}"
                        return (title, descr, potential_comment)
                    else:
                        # It's actually part of descr
                        title_full = link_text.strip()
                        # Ensure title has "gist: " prefix
                        if not title_full.lower().startswith('gist: '):
                            title_full = f"gist: {title_full}"
                        descr_full = link_text.replace('gist:', '').strip()
                        return (title_full, descr_full, None)
                else:
                    # No comment
                    title = link_text.strip()
                    # Ensure title has "gist: " prefix
                    if not title.lower().startswith('gist: '):
                        title = f"gist: {title}"
                    descr = link_text.replace('gist:', '').strip()
                    return (title, descr, None)
            
            elif host == 'github.com' or host == 'gitlab.com':
                # Format: [username/reponame - descr](url) or [username/reponame - descr - comment](url)
                parts, sep = self._split_by_separator(link_text)
                if len(parts) == 2:
                    # No comment
                    title_part = parts[0].strip()
                    descr = parts[1].strip()
                    return (title_part, descr, None)
                elif len(parts) >= 3:
                    # Has comment
                    title_part = parts[0].strip()
                    descr = parts[1].strip()
                    potential_comment = sep.join(parts[2:]).strip() if sep else ' - '.join(parts[2:]).strip()
                    # Check if potential_comment contains Chinese
                    if self._contains_chinese(potential_comment):
                        return (title_part, descr, potential_comment)
                    else:
                        # It's actually part of descr
                        descr_full = sep.join(parts[1:]).strip() if sep else ' - '.join(parts[1:]).strip()
                        return (title_part, descr_full, None)
                else:
                    # Only title, no descr
                    return (link_text.strip(), None, None)
            
            else:
                # Other links: [title](url) or [title - comment](url)
                parts, sep = self._split_by_separator(link_text, maxsplit=1)
                if sep and len(parts) == 2:
                    title = parts[0].strip()
                    potential_comment = parts[1].strip()
                    # Check if potential_comment contains Chinese
                    if self._contains_chinese(potential_comment):
                        # For x.com links, add "twitter: " prefix if not present
                        if host == 'x.com' and title and not title.lower().startswith('twitter: '):
                            title = f"twitter: {title}"
                        return (title, None, potential_comment)
                    else:
                        # It's actually part of title
                        title_full = link_text.strip()
                        # For x.com links, add "twitter: " prefix if not present
                        if host == 'x.com' and title_full and not title_full.lower().startswith('twitter: '):
                            title_full = f"twitter: {title_full}"
                        return (title_full, None, None)
                else:
                    # Only title, no comment
                    title = link_text.strip()
                    # For x.com links, add "twitter: " prefix if not present
                    if host == 'x.com' and title and not title.lower().startswith('twitter: '):
                        title = f"twitter: {title}"
                    return (title, None, None)
        
        return (None, None, None)
    
    def _build_url_comment_mapping(self):
        """Build a mapping from URL to Chinese comment by scanning markdown files once."""
        url_to_comment = {}
        excluded_files = {'Readme.md', 'Blog.md', 'Payloads.md'}
        
        # Get the parent directory (same as in MarkdownParser)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        base_path = os.path.dirname(script_dir)
        
        for root, _, files in os.walk(base_path):
            for file in files:
                if not file.endswith('.md') or file in excluded_files:
                    continue
                
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            
                            # Extract all URLs from the line first
                            url_pattern = r'https?://[^\s\)]+'
                            urls = re.findall(url_pattern, line)
                            
                            for url in urls:
                                # Clean up URL (remove trailing punctuation)
                                clean_url = re.sub(r'[.,;:!?]+$', '', url)
                                # Normalize URL (remove trailing slash)
                                normalized_url = self._normalize_url(clean_url)
                                
                                # Parse the markdown link
                                title, description, comment = self._parse_markdown_link(line, clean_url)
                                
                                # If we found a comment with Chinese, store it
                                if comment and self._contains_chinese(comment):
                                    url_to_comment[normalized_url] = comment.strip()
                
                except Exception as e:
                    print(f"Error reading {filepath}: {e}")
        
        return url_to_comment
    
    def _build_url_description_mapping(self):
        """Build a mapping from URL to description by scanning markdown files once."""
        url_to_description = {}
        excluded_files = {'Readme.md', 'Blog.md', 'Payloads.md'}
        
        # Get the parent directory (same as in MarkdownParser)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        base_path = os.path.dirname(script_dir)
        
        for root, _, files in os.walk(base_path):
            for file in files:
                if not file.endswith('.md') or file in excluded_files:
                    continue
                
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            
                            # Extract all URLs from the line first
                            url_pattern = r'https?://[^\s\)]+'
                            urls = re.findall(url_pattern, line)
                            
                            for url in urls:
                                # Clean up URL (remove trailing punctuation)
                                clean_url = re.sub(r'[.,;:!?]+$', '', url)
                                # Normalize URL (remove trailing slash)
                                normalized_url = self._normalize_url(clean_url)
                                
                                # Parse the markdown link
                                title, description, comment = self._parse_markdown_link(line, clean_url)
                                
                                # Store description if found (only for gist and github)
                                if description:
                                    url_to_description[normalized_url] = description.strip()
                
                except Exception as e:
                    print(f"Error reading {filepath}: {e}")
        
        return url_to_description
    
    def _build_url_title_mapping(self):
        """Build a mapping from URL to title by scanning markdown files once."""
        url_to_title = {}
        excluded_files = {'Readme.md', 'Blog.md', 'Payloads.md'}
        
        # Get the parent directory (same as in MarkdownParser)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        base_path = os.path.dirname(script_dir)
        
        for root, _, files in os.walk(base_path):
            for file in files:
                if not file.endswith('.md') or file in excluded_files:
                    continue
                
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            
                            # Extract all URLs from the line first
                            url_pattern = r'https?://[^\s\)]+'
                            urls = re.findall(url_pattern, line)
                            
                            for url in urls:
                                # Clean up URL (remove trailing punctuation)
                                clean_url = re.sub(r'[.,;:!?]+$', '', url)
                                # Normalize URL (remove trailing slash)
                                normalized_url = self._normalize_url(clean_url)
                                
                                # Parse the markdown link
                                title, description, comment = self._parse_markdown_link(line, clean_url)
                                
                                # Store title if found
                                if title:
                                    url_to_title[normalized_url] = title.strip()
                
                except Exception as e:
                    print(f"Error reading {filepath}: {e}")
        
        return url_to_title
    
    def show_failed_entries(self):
        """Show only failed entries from the database that exist in markdown files."""
        # Parse markdown files to get current URLs
        parsed_data = self.parser.parse_files()
        current_urls = {item['url'] for item in parsed_data}
        
        # Get all failed entries from database
        all_failed_data = self.db_manager.get_failed_entries()
        
        # Filter to only include failed entries that exist in markdown files
        filtered_data = []
        for item in all_failed_data:
            if item['url'] in current_urls:
                filtered_data.append(item)
        
        if not filtered_data:
            print("No failed entries found that exist in markdown files.")
            return
        
        print(f"Found {len(filtered_data)} failed entries (out of {len(all_failed_data)} total failed entries):")
        for i, item in enumerate(filtered_data, 1):
            print(f"ID: {i}")
            print(f"URL: {item['url']}")
            print(f"Error: {item['error']}")
            print()  # Empty line for readability
    
    def test_url(self, url):
        """Test URL parsing and return the result."""
        print(f"Testing URL: {url}")
        print("-" * 50)
        
        # Process the URL to get metadata
        metadata = self.url_processor.process_url(url)
        
        # Print the result
        print("Result:")
        print(f"  Title: {metadata['title']}")
        print(f"  Stars: {metadata['stars']}")
        print(f"  Status: {'Success' if metadata['status'] == 1 else 'Failed'}")
        if metadata['error']:
            print(f"  Error: {metadata['error']}")
        if metadata['repo_updated_at']:
            print(f"  Updated: {metadata['repo_updated_at']}")
        if metadata['repo_pushed_at']:
            print(f"  Pushed: {metadata['repo_pushed_at']}")
        
        print("-" * 50)
        return metadata
    
    def scan_comments(self):
        """Scan all markdown files and extract Chinese comments matching pattern ` - .* - (.*)`."""
        print("Scanning markdown files for Chinese comments...")
        
        comments = []
        excluded_files = {'Readme.md', 'Blog.md', 'Payloads.md'}
        
        # Get the parent directory (same as in MarkdownParser)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        base_path = os.path.dirname(script_dir)
        
        for root, _, files in os.walk(base_path):
            for file in files:
                if not file.endswith('.md') or file in excluded_files:
                    continue
                
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        line_number = 0
                        for line in f:
                            line_number += 1
                            line = line.strip()
                            if not line:
                                continue
                            
                            # Look for pattern ` - .* - 中文注释` in square brackets
                            # This matches: [title - description - 中文注释](url)
                            pattern = r'\[.*? - .*? - ([^)]+)\]\([^)]+\)'
                            matches = re.findall(pattern, line)
                            
                            for comment in matches:
                                # Check if comment contains Chinese characters
                                if self._contains_chinese(comment):
                                    comments.append({
                                        'file': file,
                                        'filepath': filepath,
                                        'line_number': line_number,
                                        'comment': comment.strip(),
                                        'full_line': line
                                    })
                
                except Exception as e:
                    print(f"Error reading {filepath}: {e}")
        
        print(f"Found {len(comments)} Chinese comments")
        return comments
    
    def _contains_chinese(self, text):
        """Check if text contains Chinese characters."""
        for char in text:
            # Check for Chinese character ranges
            if '\u4e00' <= char <= '\u9fff':  # CJK Unified Ideographs
                return True
            if '\u3400' <= char <= '\u4dbf':  # CJK Extension A
                return True
            if '\u20000' <= char <= '\u2a6df':  # CJK Extension B
                return True
            if '\u2a700' <= char <= '\u2b73f':  # CJK Extension C
                return True
            if '\u2b740' <= char <= '\u2b81f':  # CJK Extension D
                return True
            if '\u2b820' <= char <= '\u2ceaf':  # CJK Extension E
                return True
            if '\uf900' <= char <= '\ufaff':  # CJK Compatibility Ideographs
                return True
            if '\u3300' <= char <= '\u33ff':  # CJK Compatibility
                return True
        return False


def main():
    parser = argparse.ArgumentParser(description='Lists Manager - Update and dump data from markdown files')
    parser.add_argument('-u', '--update', action='store_true', help='Update local SQLite database')
    parser.add_argument('-t', '--token', type=str, help='GitHub token for API access')
    parser.add_argument('-p', '--proxy', type=str, help='HTTP/HTTPS proxy URL (e.g., http://proxy:8080)')
    parser.add_argument('-d', '--dump', action='store_true', help='Dump all data in JSON format')
    parser.add_argument('-f', '--failed', action='store_true', help='Show only failed entries')
    parser.add_argument('-df', '--delete-failed', action='store_true', help='Delete all failed entries from database')
    parser.add_argument('-a', '--all', action='store_true', help='Force update all entries (bypass age check)')
    parser.add_argument('-tu', '--test-url', type=str, help='Test URL parsing and get result')
    parser.add_argument('-du', '--dump-minimized', action='store_true', help='Dump data in minimized format (no additional outputs)')
    parser.add_argument('-dc', '--dump-comments', action='store_true', help='Scan all markdown files and extract Chinese comments matching pattern ` - .* - (.*)`')
    
    args = parser.parse_args()
    
    if not args.update and not args.dump and not args.failed and not args.delete_failed and not args.test_url and not args.dump_minimized and not args.dump_comments:
        parser.print_help()
        sys.exit(1)
    
    # Initialize the manager
    manager = ListsManager(github_token=args.token, proxy=args.proxy)
    
    if args.update:
        manager.update_database(force_update=args.all)
    
    if args.dump:
        manager.dump_data()
    
    if args.failed:
        manager.show_failed_entries()
    
    if args.delete_failed:
        deleted_count = manager.db_manager.delete_failed_entries()
        if deleted_count > 0:
            print(f"Deleted {deleted_count} failed entries from database.")
        else:
            print("No failed entries found to delete.")
    
    if args.test_url:
        manager.test_url(args.test_url)
    
    if args.dump_minimized:
        manager.dump_data_minimized()
    
    if args.dump_comments:
        comments = manager.scan_comments()
        if comments:
            print("\nChinese comments found:")
            print("=" * 80)
            for i, comment in enumerate(comments, 1):
                print(f"{i}. File: {comment['file']} (Line {comment['line_number']})")
                print(f"   Comment: {comment['comment']}")
                print(f"   Full line: {comment['full_line']}")
                print("-" * 80)
        else:
            print("No Chinese comments found matching the pattern.")


if __name__ == "__main__":
    main()
