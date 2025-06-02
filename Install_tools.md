Install Tools for Darkness Recon
This guide provides comprehensive instructions to install all required tools for the darkness_recon.sh script, ensuring a robust setup for advanced reconnaissance, subdomain enumeration, and scanning. The tools are categorized by installation method, with commands tested for Ubuntu/Debian-based systems (e.g., Ubuntu 22.04 or later). Adjust for other distributions as needed.
Prerequisites

System: Ubuntu/Debian-based Linux.
Dependencies: Install essential packages:sudo apt update && sudo apt install -y git curl python3 python3-pip snapd build-essential libpcap-dev ruby ruby-dev chromium-browser
sudo snap install go --classic


Go Environment: Configure GOPATH:echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
source ~/.bashrc


Python: Update pip:pip3 install --upgrade pip


Node.js: Install for apiscope:curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs


Docker: Install for trufflehog:sudo apt install -y docker.io
sudo systemctl enable docker --now
sudo usermod -aG docker $USER



Tool Installation
1. Package Manager (APT)
Install tools via apt:
sudo apt install -y subfinder assetfinder amass findomain gobuster httpx-toolkit katana dnsx dnsrecon nmap masscan dnsenum jq dirsearch whatweb

Grant masscan raw packet permissions:
sudo setcap cap_net_raw+eip /usr/bin/masscan

2. Go-Based Tools
Install Go-based tools:
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/hakluke/haktrails@latest
go install github.com/hahwul/gauplus@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/LukaSikic/subzy@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/OWASP/Amass/v4/cmd/amass@latest
go install github.com/tomnomnom/gf@latest
go install github.com/haccer/subjack@latest

Update nuclei templates:
nuclei -update-templates

3. Python-Based Tools
Install Python-based tools:
pip3 install sublist3r waymore wafw00f spiderfoot gospider paramspider arjun cloud_enum sslyze commonspeak2

Install sublert:
git clone https://github.com/yassineaboukir/sublert.git
cd sublert
pip3 install -r requirements.txt
sudo python3 setup.py install
cd .. && rm -rf sublert

Install dnsvalidator:
git clone https://github.com/vortexau/dnsvalidator.git
cd dnsvalidator
pip3 install -r requirements.txt
python3 setup.py install
cd .. && rm -rf dnsvalidator

4. Manual Installation (GitHub Repositories)
Install tools requiring manual setup:

altdns:
git clone https://github.com/infosec-au/altdns.git
cd altdns
pip3 install -r requirements.txt
sudo python3 setup.py install
cd .. && rm -rf altdns


dnsgen:
git clone https://github.com/ProjectAnte/dnsgen.git
cd dnsgen
pip3 install -r requirements.txt
sudo python3 setup.py install
cd .. && rm -rf dnsgen


ctfr:
git clone https://github.com/UnaPibaGeek/ctfr.git
cd ctfr
pip3 install -r requirements.txt
sudo cp ctfr.py /usr/local/bin/ctfr
sudo chmod +x /usr/local/bin/ctfr
cd .. && rm -rf ctfr


knockpy:
git clone https://github.com/guelfoweb/knock.git
cd knock
pip3 install -r requirements.txt
sudo python3 setup.py install
cd .. && rm -rf knock


cero:
git clone https://github.com/glebarez/cero.git
cd cero
go build
sudo mv cero /usr/local/bin/
cd .. && rm -rf cero


bhedak:
git clone https://github.com/R0X4R/bhedak.git
cd bhedak
pip3 install -r requirements.txt
sudo cp bhedak.py /usr/local/bin/bhedak
sudo chmod +x /usr/local/bin/bhedak
cd .. && rm -rf bhedak


bbot:
pip3 install bbot


dnsmap:
git clone https://github.com/resurrecting-open-source-projects/dnsmap.git
cd dnsmap
make
sudo make install
cd .. && rm -rf dnsmap


aquatone:
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
sudo mv aquatone /usr/local/bin/
rm -rf aquatone_linux_amd64_1.7.0.zip LICENSE.txt


sdgo (SubDomainizer):
git clone https://github.com/We5ter/SubDomainizer.git
cd SubDomainizer
pip3 install -r requirements.txt
sudo cp SubDomainizer.py /usr/local/bin/sdgo
sudo chmod +x /usr/local/bin/sdgo
cd .. && rm -rf SubDomainizer


gitrob:
go install github.com/michenriksen/gitrob@latest


ratelimitr:
go install github.com/projectdiscovery/ratelimitr/cmd/ratelimitr@latest


gf Patterns:
git clone https://github.com/1ndianl33t/Gf-Patterns.git
mkdir -p ~/.gf
cp Gf-Patterns/*.json ~/.gf/
rm -rf Gf-Patterns



5. Node.js-Based Tools
Install apiscope:
npm install -g @apiscope/cli

6. Docker-Based Tools
Install trufflehog:
docker pull trufflesecurity/trufflehog
alias trufflehog='docker run --rm -v "$(pwd):/pwd" trufflesecurity/trufflehog'
echo "alias trufflehog='docker run --rm -v \"\$(pwd):/pwd\" trufflesecurity/trufflehog'" >> ~/.bashrc
source ~/.bashrc

7. EyeWitness
Install EyeWitness:
git clone https://github.com/FortyNorthSecurity/EyeWitness.git
cd EyeWitness/Python/setup
sudo ./setup.sh
cd ../../.. && rm -rf EyeWitness

8. SecLists
Install SecLists:
sudo apt install -y seclists || {
    git clone https://github.com/danielmiessler/SecLists.git
    sudo mv SecLists /usr/share/seclists
}

9. Configuration

Amass: Configure API keys:
mkdir -p ~/.config/amass
nano ~/.config/amass/config.ini
# Add API keys (e.g., Censys, Shodan): https://github.com/OWASP/Amass/blob/master/doc/user_guide.md

Update script with path: /path/to/amass-config.ini.

Subjack: Download fingerprints:
wget https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -O ~/subjack-fingerprints.json

Update script with path: /path/to/subjack-fingerprints.json.

BBOT: Configure API keys:
mkdir -p ~/.bbot
nano ~/.bbot/config.yml
# Add API keys (e.g., Shodan, Censys): https://github.com/blacklanternsecurity/bbot

Update script with path: /path/to/bbot-config.yml.

Nmap Scripts: Update scripts:
sudo nmap --script-updatedb

Update script with path: /usr/share/nmap/scripts.

Resolvers: Script updates dynamically, but ensure /path/to/resolvers.txt is writable.


10. Verification
Verify installations:
for tool in subfinder assetfinder amass findomain sublist3r gobuster httpx katana dnsx puredns dnsrecon altdns shuffledns haktrails dnsgen ctfr knockpy cero bhedak bbot spiderfoot gospider hakrawler paramspider gf ffuf wafw00f nuclei subjack subzy nmap masscan naabu dnsenum sublert dnsmap aquatone arjun sdgo cloud_enum dirsearch sslyze commonspeak2 apiscope whatweb gitrob dnsvalidator trufflehog ratelimitr anew unfurl jq EyeWitness; do
    command -v "$tool" >/dev/null && echo "$tool installed" || echo "$tool not installed"
done

Notes

Permissions: masscan, nmap require sudo; Docker requires root or group permissions.
API Keys: Configure for amass, findomain, bbot, spiderfoot, cloud_enum, findmain, bbot, spiderfoot, cloud_enum.
System Load: Adjust BASE_THREADS=150 if overloaded; dynamically scaled.
Updates: Regularly update tools (go install ...@latest, pip install --upgrade ..., nuclei -update-tables).
Custom Paths: Update RESOLVERS, WORDLIST, WEB_WORDLIST, API_WORDLIST, NMAP_SCRIPTS, amass-config, subjack-fingerprints, bbot-config.
Troubleshooting: Check GitHub repositories for issues; ensure chromium for aquatone; verify Docker for trufflehog.

This setup ensures all tools are installed and configured for darkness_recon.sh to deliver unparalleled performance and output.
