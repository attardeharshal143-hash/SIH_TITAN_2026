# Optional Development & Lab Scripts

These scripts are **optional development utilities** for generating synthetic IPsec traffic in a Linux lab using strongSwan and network namespaces.

### Note on Production Independence:
- **None of these scripts are executed or required by the production web application or backend API.**
- The production TITAN IPsec Analyzer analyzes standard `.pcap` files directly and runs in any standard Python cloud or server environment without requiring Linux kernel namespaces, `sudo`, or strongSwan.
