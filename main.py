from ssh_operations import run_tcpdump, download_tcpdump
from analysis import analyze_dump, analyze_attack
from report import generate_html_report

if __name__ == "__main__":
    run_tcpdump()
    download_tcpdump()
    analysis_results = analyze_dump()
    details = analyze_attack(analysis_results)
    generate_html_report(details)