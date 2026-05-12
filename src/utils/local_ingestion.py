"""
Local code ingestion with tree-sitter chunking for better scalability.
Replaces the naive string concatenation approach with structured document chunking.
"""

import os
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript
from tree_sitter import Language, Parser, Node
import chromadb
from chromadb.utils import embedding_functions
import logging

logger = logging.getLogger(__name__)

class CodeChunker:
    """Chunks code files into semantic units using tree-sitter."""

    def __init__(self):
        # Initialize parsers for different languages
        self.parsers = {
            '.py': Parser(Language(tspython.language())),
            '.js': Parser(Language(tsjavascript.language())),
            '.jsx': Parser(Language(tsjavascript.language())),
            '.ts': Parser(Language(tsjavascript.language())),
            '.tsx': Parser(Language(tsjavascript.language())),
        }

        # Initialize ChromaDB client
        self.chroma_client = chromadb.PersistentClient(path="./chroma_db")
        self.embedding_function = embedding_functions.DefaultEmbeddingFunction()

        # Create or get collection for code chunks
        try:
            self.collection = self.chroma_client.create_collection(
                name="code_chunks",
                embedding_function=self.embedding_function
            )
        except:
            self.collection = self.chroma_client.get_collection(
                name="code_chunks",
                embedding_function=self.embedding_function
            )

    def _get_parser(self, file_path: str) -> Optional[Parser]:
        """Get the appropriate parser for a file extension."""
        ext = Path(file_path).suffix.lower()
        return self.parsers.get(ext)

    def _extract_functions_and_classes(self, tree, source_code: bytes, file_path: str) -> List[Dict[str, Any]]:
        """Extract functions and classes from the AST."""
        chunks = []

        def extract_node_info(node: Node, node_type: str) -> Dict[str, Any]:
            """Extract information from a node."""
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1

            # Get the node's text
            node_text = source_code[node.start_byte:node.end_byte].decode('utf-8', errors='ignore')

            # Try to extract name
            name = "unknown"
            for child in node.children:
                if child.type == 'identifier':
                    name = source_code[child.start_byte:child.end_byte].decode('utf-8', errors='ignore')
                    break

            # Try to extract docstring for Python
            docstring = ""
            if node_type in ['function_definition', 'class_definition'] and len(node.children) > 2:
                for child in node.children:
                    if child.type == 'block' or child.type == 'statement_block':
                        first_stmt = child.children[0] if child.children else None
                        if first_stmt and first_stmt.type == 'expression_statement':
                            expr = first_stmt.children[0] if first_stmt.children else None
                            if expr and expr.type == 'string':
                                docstring = source_code[expr.start_byte:expr.end_byte].decode('utf-8', errors='ignore')
                                docstring = docstring.strip('"\'')
                        break

            return {
                'type': node_type,
                'name': name,
                'file_path': file_path,
                'start_line': start_line,
                'end_line': end_line,
                'content': node_text,
                'docstring': docstring,
                'chunk_id': hashlib.md5(f"{file_path}:{name}:{start_line}".encode()).hexdigest()
            }

        def traverse(node: Node):
            """Recursively traverse the AST."""
            # Python nodes
            if node.type in ['function_definition', 'async_function_definition']:
                chunks.append(extract_node_info(node, 'function'))
            elif node.type == 'class_definition':
                chunks.append(extract_node_info(node, 'class'))
            # JavaScript/TypeScript nodes
            elif node.type in ['function_declaration', 'arrow_function', 'function_expression']:
                chunks.append(extract_node_info(node, 'function'))
            elif node.type in ['class_declaration', 'class']:
                chunks.append(extract_node_info(node, 'class'))

            # Continue traversing
            for child in node.children:
                traverse(child)

        traverse(tree.root_node)
        return chunks

    def chunk_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Chunk a single file into semantic units."""
        parser = self._get_parser(file_path)
        if not parser:
            # For non-supported files, create a single chunk
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                return [{
                    'type': 'file',
                    'name': Path(file_path).name,
                    'file_path': file_path,
                    'start_line': 1,
                    'end_line': len(content.splitlines()),
                    'content': content[:5000],  # Limit content size
                    'docstring': '',
                    'chunk_id': hashlib.md5(f"{file_path}:full".encode()).hexdigest()
                }]
            except Exception as e:
                logger.error(f"Error reading file {file_path}: {e}")
                return []

        try:
            with open(file_path, 'rb') as f:
                source_code = f.read()

            tree = parser.parse(source_code)
            chunks = self._extract_functions_and_classes(tree, source_code, file_path)

            # If no chunks extracted, create one for the whole file
            if not chunks:
                chunks = [{
                    'type': 'file',
                    'name': Path(file_path).name,
                    'file_path': file_path,
                    'start_line': 1,
                    'end_line': len(source_code.decode('utf-8', errors='ignore').splitlines()),
                    'content': source_code.decode('utf-8', errors='ignore')[:5000],
                    'docstring': '',
                    'chunk_id': hashlib.md5(f"{file_path}:full".encode()).hexdigest()
                }]

            return chunks

        except Exception as e:
            logger.error(f"Error parsing file {file_path}: {e}")
            return []

    def ingest_directory(self, directory_path: str, extensions: List[str] = None) -> Tuple[List[Dict], str]:
        """
        Ingest all code files from a directory and store in ChromaDB.
        Returns tuple of (chunks, collection_id).
        """
        if extensions is None:
            # Include ALL common file types for security analysis
            extensions = [
                # Code files
                '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.cpp', '.c', '.h', '.cs', '.go', '.rs', '.rb', '.php',
                # Config files
                '.json', '.yml', '.yaml', '.xml', '.toml', '.ini', '.cfg', '.conf',
                # Documentation
                '.md', '.txt', '.rst',
                # Environment/secrets (CRITICAL for security!)
                '.env', '.env.local', '.env.production',
                # Scripts
                '.sh', '.bash', '.ps1', '.bat',
                # Web files
                '.html', '.css', '.scss',
                # Database
                '.sql',
                # Requirements/dependencies
                '.requirements', 'requirements.txt', 'package.json', 'Gemfile', 'Cargo.toml'
            ]

        all_chunks = []
        documents = []
        metadatas = []
        ids = []

        logger.info(f"Scanning directory: {directory_path}")
        files_found = []

        # Also check for specific filenames without extensions
        important_files = ['requirements', 'Dockerfile', 'Makefile', 'README', '.gitignore', '.dockerignore']

        for root, _, files in os.walk(directory_path):
            for file in files:
                # Check extensions OR important filenames
                if any(file.endswith(ext) for ext in extensions) or file in important_files:
                    file_path = os.path.join(root, file)
                    files_found.append(file_path)
                    logger.debug(f"Found file: {file_path}")
                    chunks = self.chunk_file(file_path)

                    for chunk in chunks:
                        all_chunks.append(chunk)

                        # Prepare for ChromaDB
                        doc_text = f"{chunk['type']} {chunk['name']} in {chunk['file_path']}\n"
                        doc_text += f"Lines {chunk['start_line']}-{chunk['end_line']}\n"
                        if chunk['docstring']:
                            doc_text += f"Docstring: {chunk['docstring']}\n"
                        doc_text += f"\n{chunk['content']}"

                        documents.append(doc_text)
                        metadatas.append({
                            'type': chunk['type'],
                            'name': chunk['name'],
                            'file_path': chunk['file_path'],
                            'start_line': chunk['start_line'],
                            'end_line': chunk['end_line']
                        })
                        ids.append(chunk['chunk_id'])

        # Store in ChromaDB
        if documents:
            self.collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            logger.info(f"Ingested {len(documents)} chunks from {len(files_found)} files in {directory_path}")

        return all_chunks, self.collection.name

    def search_chunks(self, query: str, n_results: int = 10) -> List[Dict[str, Any]]:
        """Search for relevant code chunks using vector similarity."""
        results = self.collection.query(
            query_texts=[query],
            n_results=n_results
        )

        formatted_results = []
        if results['metadatas'] and results['documents']:
            for i, (meta, doc) in enumerate(zip(results['metadatas'][0], results['documents'][0])):
                formatted_results.append({
                    'metadata': meta,
                    'content': doc,
                    'distance': results['distances'][0][i] if results['distances'] else None
                })

        return formatted_results


def ingest_local_files(file_paths: List[str]) -> Tuple[List[Dict], str]:
    """
    Main entry point for ingesting local files.
    Compatible with existing API.
    """
    chunker = CodeChunker()
    all_chunks = []

    for file_path in file_paths:
        if os.path.isdir(file_path):
            chunks, collection_id = chunker.ingest_directory(file_path)
            all_chunks.extend(chunks)
        elif os.path.isfile(file_path):
            chunks = chunker.chunk_file(file_path)
            all_chunks.extend(chunks)

            # Add to ChromaDB
            for chunk in chunks:
                doc_text = f"{chunk['type']} {chunk['name']} in {chunk['file_path']}\n"
                doc_text += f"Lines {chunk['start_line']}-{chunk['end_line']}\n"
                if chunk['docstring']:
                    doc_text += f"Docstring: {chunk['docstring']}\n"
                doc_text += f"\n{chunk['content']}"

                chunker.collection.add(
                    documents=[doc_text],
                    metadatas=[{
                        'type': chunk['type'],
                        'name': chunk['name'],
                        'file_path': chunk['file_path'],
                        'start_line': chunk['start_line'],
                        'end_line': chunk['end_line']
                    }],
                    ids=[chunk['chunk_id']]
                )

    return all_chunks, chunker.collection.name