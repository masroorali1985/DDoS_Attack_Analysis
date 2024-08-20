import os
from jinja2 import Template
from config import local_dir, timestamp

def generate_html_report(details):
    template = Template("""
    <html>
    <head><title>DDoS Attack Analysis Report</title></head>
    <body>
        <h1>DDoS Attack Analysis Report</h1>

        <h2>ICMP Flood Attack Details</h2>
        <table border="1">
            <tr>
                <th>Source IP</th>
                <th>Country</th>
                <th>Packet Count</th>
            </tr>
            {% for detail in details["icmp_attackers"] %}
            <tr>
                <td>{{ detail["source_ip"] }}</td>
                <td>{{ detail["source_country"] }}</td>
                <td>{{ detail["packet_count"] }}</td>
            </tr>
            {% endfor %}
        </table>

        <h2>UDP Flood Attack Details</h2>
        <table border="1">
            <tr>
                <th>Source IP</th>
                <th>Country</th>
                <th>Packet Count</th>
            </tr>
            {% for detail in details["udp_attackers"] %}
            <tr>
                <td>{{ detail["source_ip"] }}</td>
                <td>{{ detail["source_country"] }}</td>
                <td>{{ detail["packet_count"] }}</td>
            </tr>
            {% endfor %}
        </table>

        <h2>TCP SYN Flood Attack Details</h2>
        <table border="1">
            <tr>
                <th>Source IP</th>
                <th>Country</th>
                <th>Packet Count</th>
            </tr>
            {% for detail in details["tcp_syn_attackers"] %}
            <tr>
                <td>{{ detail["source_ip"] }}</td>
                <td>{{ detail["source_country"] }}</td>
                <td>{{ detail["packet_count"] }}</td>
            </tr>
            {% endfor %}
        </table>

        <h2>TCP RST/FIN Flood Attack Details</h2>
        <table border="1">
            <tr>
                <th>Source IP</th>
                <th>Country</th>
                <th>Packet Count</th>
            </tr>
            {% for detail in details["tcp_rst_fin_attackers"] %}
            <tr>
                <td>{{ detail["source_ip"] }}</td>
                <td>{{ detail["source_country"] }}</td>
                <td>{{ detail["packet_count"] }}</td>
            </tr>
            {% endfor %}
        </table>

        <h2>IP Fragmentation</h2>
        <p><strong>Fragmented Packets:</strong> {{ details["fragmented_packets"] }}</p>

        <h2>Repetitive Payloads (Brute-Force Style Attack)</h2>
        <table border="1">
            <tr>
                <th>Source IP</th>
                <th>Repetitive Payload Count</th>
            </tr>
            {% for src_ip, count in details["repetitive_payloads"].items() %}
            <tr>
                <td>{{ src_ip }}</td>
                <td>{{ count }}</td>
            </tr>
            {% endfor %}
        </table>

        <h2>Other Indicators</h2>
        {% if details["unusual_packet_size"] %}
        <p><strong>Unusual Packet Size:</strong> {{ details["unusual_packet_size"] }}</p>
        {% endif %}
        {% if details["malformed_packets"] %}
        <p><strong>Malformed Packets:</strong> {{ details["malformed_packets"] }}</p>
        {% endif %}
    </body>
    </html>
    """)

    html_content = template.render(details=details)

    report_path = os.path.join(local_dir, f"flood_attack_report_{timestamp}.html")
    with open(report_path, "w") as report_file:
        report_file.write(html_content)

    print(f"Report generated: {report_path}")