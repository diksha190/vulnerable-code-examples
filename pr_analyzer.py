#!/usr/bin/env python3
"""
PR Analyzer - Analyzes changed files in a Pull Request
"""

import json
import sys
import argparse
from pathlib import Path
from src.core.analyzer import UniversalSecurityAnalyzer


def analyze_pr(changed_files_path: str, output_path: str):
    """Analyze all changed files in PR"""
    
    # Read changed files
    with open(changed_files_path, 'r') as f:
        changed_files = [line.strip() for line in f if line.strip()]
    
    print(f"📄 Analyzing {len(changed_files)} changed files...")
    
    # Initialize analyzer
    analyzer = UniversalSecurityAnalyzer()
    
    results = {
        'total_vulnerabilities': 0,
        'total_files': len(changed_files),
        'total_cost': 0.0,
        'files': []
    }
    
    # Analyze each file
    for filepath in changed_files:
        # Skip non-code files
        if not Path(filepath).exists():
            print(f"⚠️  Skipped (not found): {filepath}")
            continue
        
        ext = Path(filepath).suffix
        if ext not in ['.py', '.js', '.ts', '.sol', '.rs', '.go']:
            print(f"⚠️  Skipped (not supported): {filepath}")
            continue
        
        print(f"\n🔍 Analyzing: {filepath}")
        
        try:
            # Analyze file
            result = analyzer.analyze_file(filepath)
            
            vulns = result.get('vulnerabilities', [])
            cost = result.get('metadata', {}).get('cost_usd', 0)
            
            results['total_vulnerabilities'] += len(vulns)
            results['total_cost'] += cost
            
            results['files'].append({
                'path': filepath,
                'language': result['metadata']['language'],
                'vulnerabilities': vulns,
                'summary': result.get('summary', {}),
                'cost': cost
            })
            
            print(f"  ✅ Found {len(vulns)} vulnerabilities (${cost:.4f})")
            
        except Exception as e:
            print(f"  ❌ Error: {e}")
            results['files'].append({
                'path': filepath,
                'error': str(e),
                'vulnerabilities': []
            })
    
    # Save results
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n📊 Summary:")
    print(f"  Total files: {results['total_files']}")
    print(f"  Vulnerabilities: {results['total_vulnerabilities']}")
    print(f"  Total cost: ${results['total_cost']:.4f}")
    print(f"\n💾 Results saved to: {output_path}")
    
    return results


def main():
    parser = argparse.ArgumentParser(description='Analyze PR changed files')
    parser.add_argument('--repo', required=True, help='Repository (owner/name)')
    parser.add_argument('--pr-number', required=True, help='PR number')
    parser.add_argument('--changed-files', required=True, help='File with changed files list')
    parser.add_argument('--output', required=True, help='Output JSON file')
    
    args = parser.parse_args()
    
    print(f"🚀 AI Security PR Analyzer")
    print(f"📦 Repository: {args.repo}")
    print(f"🔀 PR Number: #{args.pr_number}")
    print("="*60)
    
    try:
        analyze_pr(args.changed_files, args.output)
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()