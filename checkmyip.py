#!/usr/bin/python

"""
CheckMyIP Server

Written by: John W Kerns
Website: http://blog.packetsar.com
Repository: https://github.com/packetsar/checkmyip
"""

# Import python native modules and third party modules
import os
import time
import socket
import jinja2
import paramiko
import threading
import uuid

# Inform version here
version = "v1.4.1"

# Jinja formatting for logging queries
j2log = "Connection from: {{ ip }} ({{ port }}) ({{ proto }}) (request: {{ requestid }})"

# Jinja formatting for response queries
j2send = """{
"comment": "##     Your IP Address is {{ ip }} ({{ port }})     ##",
"family": "{{ family }}",
"ip": "{{ ip }}",
"port": "{{ port }}",
"protocol": "{{ proto }}",
"hostname": "{{ hostname }}",
"request": "{{ requestid }}",
"version": "%s",
"forked-from": "https://github.com/packetsar/checkmyip"
}""" % version


class log_management:
    """
    Handles all printing to console and logging to the logfile
    Publishes two global methods:
        - log(data)     : Logs data to logfile and console with timestamp
        - console(data) : Prints data to console without timestamp
    """
    def __init__(self):
        self.logpath = os.path.join(os.getcwd(), "logs")  # Log file directory path
        self.logfile = os.path.join(self.logpath, "%scheckmyip.log" % \
                       time.strftime("%Y-%m-%d_"))  # Log file full path
        self.paramikolog = os.path.join(self.logpath, "%sssh.log" % \
                           time.strftime("%Y-%m-%d_"))  # SSH log file path
        self.thread = threading.Thread(target=self._change_logfiles)
        self.thread.daemon = True
        self.thread.start()  # Start talker thread to listen to port
        self._publish_methods()  # Publish the console and log methods to glob
        self.can_log = True  # Variable used to check if we can log
        try:  # Try to configure the SSH log file, create dir if fail
            paramiko.util.log_to_file(self.paramikolog)
        except IOError:
            self._create_log_dir()

    def _logger(self, data):
        """
        Logging method published to global as 'log'
        Args:
            data (str): Data to log to logfile and console
        Raises:
            IOError: If unable to write to logfile
        """
        logdata = time.strftime("%Y-%m-%d %H:%M:%S") + ":   " + data + "\n"
        if self.can_log:
            try:  # Try to write to log, create log dir if fail
                f = open(self.logfile, 'a')
                f.write(logdata)
                f.close()
            except IOError:
                self._console("Unable to log to logfile %s. Creating log directory" % self.logfile)
                self.can_log = False
                self._create_log_dir()
        self._console(logdata)

    def _console(self, data, timestamp=False):
        if timestamp:
            logdata = time.strftime("%Y-%m-%d %H:%M:%S") + ":   " + data + "\n"
        else:
            logdata = data
        print(logdata, flush=True)

    def _publish_methods(self):
        global log
        global console
        log = self._logger  # Global method used to write to the log file
        console = self._console  # Global method used to write to the console

    def _create_log_dir(self):
        """
        Create the directory for logging
        Raises:
            Exception: If unable to create the log directory
        """
        os.system('mkdir -p ' + self.logpath)
        self._console("Logpath (%s) created" % self.logpath)
        self.can_log = True

    def _change_logfiles(self, thread=True):
        while True:
            time.sleep(10)
            self.logfile = os.path.join(self.logpath, "%scheckmyip.log" % \
                           time.strftime("%Y-%m-%d_"))  # Log file full path
            self.paramikolog = os.path.join(self.logpath, "%sssh.log" % \
                               time.strftime("%Y-%m-%d_"))  # SSH log file path
            paramiko.util.log_to_file(self.paramikolog)


class rsa_key:
    """
    RSA key class used to create a paramiko RSAKey object from a hardcoded
    private key string.
    Publishes a callable method that returns the paramiko.RSAKey object.
    """
    def readlines(self):
        """
        Initialize and read the RSA key object, Checks for existing RSA key file,
        if not found generates a new one
        Raises:
            Exception: If unable to load or generate the RSA key.
        """
        self.key_bits = 2048
        self.private_key_path = os.path.join(os.getcwd(), "id_rsa")
        key_exists = os.path.isfile(self.private_key_path)
        if not key_exists:
            log("Generating new RSA key at %s" % self.private_key_path)
            key = paramiko.RSAKey.generate(bits=self.key_bits, progress_func=self.key_creation_progress_func)
            key.write_private_key_file(self.private_key_path)
            log("RSA key generation complete")
        try:
            self.data = paramiko.RSAKey.from_private_key_file(self.private_key_path).get_private_key_str()  
        except (paramiko.ssh_exception.SSHException, paramiko.ssh_exception.SSHException) :
            log("Failed to load RSA key from %s" % self.private_key_path)
            os.move(self.private_key_path, self.private_key_path + ".corrupt")
            log("Renamed corrupt key to %s.corrupt" % self.private_key_path)
            return self.readlines()  # Retry reading the key
        except Exception:   
            raise
        return self.data.splitlines(keepends=True)
    
    def key_creation_progress_func(self, completed, total):
        """Progress function for RSA key generation"""
        percent_complete = (completed / total) * 100
        log(f"Generating RSA Key: {percent_complete:.2f}% complete", timestamp=True)

    def __call__(self):
        """Recursive method uses own object as arg when called"""
        return paramiko.RSAKey.from_private_key(self)


class ssh_server(paramiko.ServerInterface):
    """
    Imports and modifies the ServerInterface module for use by paramiko
    """
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_none(self, username):
        """Auth none method left wide open"""
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        """Give no auth options"""
        return 'none'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes):
        return True


def j2format(j2tmp, valdict):
    """Method to merge Jinja templates with value dictionary"""
    template = jinja2.Template(j2tmp)
    return template.render(valdict).replace("\n", "\r\n")


def clean_ip(addr):
    """Cleans IP addresses coming from socket library"""
    ip = addr[0]
    port = addr[1]
    if len(ip) > 6:  # If this IP is not a super short v6 address
        if ip[:7] == "::ffff:":  # If this is a prefixed IPv4 address
            ip = ip.replace("::ffff:", "")  # Return the cleaned IP
    return ip, port  # Return the uncleaned IP if not matched


def get_ip_family(ip):
    """
    Determines if an IP address is IPv4, IPv6, or undefined
    Args:
        ip (str): The IP address to check
    Returns:
        str: "ipv4", "ipv6", or "undefined"
    """
    def is_ipv4(s):
        try:
            return str(int(s)) == s and 0 <= int(s) <= 255
        except Exception:
            return False

    def is_ipv6(s):
        if len(s) == 0:
            return True
        if len(s) > 4:
            return False
        try:
            return int(s, 16) >= 0 and s[0] != '-'
        except Exception:
            return False

    if ip.count(".") == 3 and all(is_ipv4(i) for i in ip.split(".")):
        return "ipv4"
    if ip.count(":") > 1 and all(is_ipv6(i) for i in ip.split(":")):
        return "ipv6"
    return "undefined"


def listener(port, talker):
    """
    TCP listener methods. Gets used once for each listening port
    Args:
        port (int): The TCP port to listen on
        talker (function): The talker function to handle incoming connections
    Raises:
        Exception: If unable to bind to the specified port.
    """
    listen_ip = ''
    listen_port = port
    buffer_size = 1024
    while True:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)  # v6 family
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((listen_ip, listen_port))
        sock.listen(buffer_size)
        client, address = sock.accept()
        ip, port = clean_ip(address)  # Get all cleaned IP info
        # Hostname is resolved doing inverse dns lookup
        hostname, tmp_port = socket.getnameinfo((ip, 0), 0)
        ip_family = get_ip_family(ip)
        valdict = {"ip": ip, "port": port, "family": ip_family, "hostname": hostname}  # Put in dict
        thread = threading.Thread(target=talker, args=(client, valdict))
        thread.start()  # Start talker thread to listen to port


def telnet_talker(client, valdict, proto="telnet"):
    """
    Telnet responder method. Is run in own thread for each telnet query
    Args:
        client (socket): The client socket object
        valdict (dict): The value dictionary for Jinja templating
        proto (str): The protocol string to use in the response
    Raises:
        Exception: If unable to send data to the client.
    """
    request_id = uuid.uuid4()
    valdict.update({"proto": proto, "requestid": request_id})  # Add protocol and requestid to dict
    log(j2format(j2log, valdict))  # Log the query to the console and logfile
    # Send the query response
    client.send(f'{j2format(j2send, valdict)}\n'.encode())
    time.sleep(1)  # Wait a second
    client.close()  # Close the channel


def ssh_talker(client, valdict, proto="ssh"):
    """
    SSH responder method. Gets run in own thread for each SSH query
    Args:
        client (socket): The client socket object
        valdict (dict): The value dictionary for Jinja templating
        proto (str): The protocol string to use in the response
    Raises:
        Exception: If unable to send data to the client.
    """
    def makefile():  # A hack to make Cisco SSH sessions work properly
        chan.makefile('rU').readline().strip('\r\n')

    request_id = uuid.uuid4()
    valdict.update({"proto": proto, "requestid": request_id})  # Add protocol and requestid to dict
    log(j2format(j2log, valdict))
    t = paramiko.Transport(client, gss_kex=True)
    t.set_gss_host(socket.getfqdn(""))
    t.load_server_moduli()
    t.add_server_key(rsa_key()())  # RSA key object nested call
    server = ssh_server()
    t.start_server(server=server)
    chan = t.accept(20)
    if chan:
        server.event.wait(10)
        chan.send('%s\n' % j2format(j2send, valdict))  # Send the response
        thread = threading.Thread(target=makefile)
        thread.start()  # Start hack in thread since it hangs indefinately
        time.sleep(1)  # Wait a second
        chan.close()  # And kill the SSH channel
    client.close()  # And kill the session


def http_talker(client, valdict, proto="http"):
    """
    HTTP responder method. Gets run in own thread for each HTTP query
    Automatically detects if client is a browser or a telnet client
    Args:
        client (socket): The client socket object
        valdict (dict): The value dictionary for Jinja templating
        proto (str): The protocol string to use in the response
    Raises:
        Exception: If unable to send data to the client.
    """
    time.sleep(.1)  # Sleep to allow the client to send some data
    client.setblocking(0)  # Set the socket recv as non-blocking
    browser = False  # Is the client using a browser?
    raw_request = ''
    request_id = uuid.uuid4()
    valdict.update({"requestid": request_id})  # Add requestid to dict

    try:  # client.recv() will raise an error if the buffer is empty
        raw_request = client.recv(2048).decode('utf-8')  # Recieve data from the buffer (if any)
        print(raw_request)  # Print to stdout
        browser = True  # Set client browser to True
    except Exception:  # If buffer was empty, then like a telnet client on TCP80
        browser = False  # Set client browser to False
    if not browser:  # If the client is not a browser
        telnet_talker(client, valdict, "http-telnet")  # Hand to telnet_talker
    else:  # If client is a browser
        temp_split = [i.strip() for i in raw_request.splitlines()]
        if -1 == temp_split[0].find('HTTP'):
            raise Exception('Incorrect Protocol')
        # Figure out our request method, path, and which version of HTTP we're using
        raw_method, raw_path, raw_protocol = [i.strip() for i in temp_split[0].split()]

        # Create the headers, but only if we have a GET reqeust
        headers = {}
        if 'GET' == raw_method:
            for k, v in [i.split(':', 1) for i in temp_split[1:-1]]:
                headers[k.strip()] = v.strip()
        else:
            raise Exception('Only accepts GET requests')

        forwarded_ip_list = headers.get('X-Forwarded-For')

        # If HTTP request was forwarded we update the info
        if forwarded_ip_list is not None and len(forwarded_ip_list) > 0:
            x_forwarded_ips = forwarded_ip_list.split(',')
            ip_family = get_ip_family(x_forwarded_ips[0].strip())
            valdict.update({"ip": x_forwarded_ips[0].strip()})
            valdict.update({"family": ip_family})
            # Hostname is resolved doing inverse dns lookup
            hostname, tmp_port = socket.getnameinfo((x_forwarded_ips[0].strip(), 0), 0)
            valdict.update({"hostname": hostname})

        valdict.update({"proto": proto})  # Add protocol to dict
        # Proceed with standard HTTP response (with headers)
        log(j2format(j2log, valdict))
        response_body_raw = j2format(j2send, valdict) + "\n"
        response_headers_raw = """HTTP/1.1 200 OK
Content-Length: %s
Content-Type: application/json; encoding=utf8
X-Request-ID: %s
Connection: close""" % (str(len(response_body_raw)), request_id)  # Response with headers
        client.send(f'{response_headers_raw}\n\n{response_body_raw}'.encode())
        client.close()


def start():
    """
    Server startup method. Starts a listener thread for each TCP port
    Raises:
        Exception: If unable to start a listener on any port.
    """
    talkers = {22: ssh_talker, 23: telnet_talker,
               80: http_talker}  # Three listeners on different ports
    for talker in talkers:
        # Launch a thread for each listener
        thread = threading.Thread(target=listener,
                                  args=(talker, talkers[talker]))
        thread.daemon = True
        thread.start()
    while True:  # While loop to allow a CTRL-C interrupt when interactive
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            quit()


class CheckMyIP_Client:
    """
    CheckMyIP_Client class used to make API calls to a CheckMyIP server.
    3 protocols are supported:
        - "telnet" : Connect via telnet (port 23)
        - "ssh"    : Connect via SSH (port 22)
        - "http"   : Connect via HTTP (port 80)
    Example usage:
        client = CheckMyIP_Client()  # Instantiate the client
        client.set_family("auto")    # Set the address family type
        data = client.get()          # Get the IP information
    Returns:
        dict: A dictionary containing the IP information.
    Raises:
        Exception: If unable to connect to the server.
    """
    def __init__(self):
        self._json = __import__('json')  # Import the JSON library
        self._socket = __import__('socket')  # Import the socket library
        self._raw_data = None  # Initialize the _raw_data variable
        self._data = None  # Initialize the _data variable
        self._af = "auto"  # Set the IP address family type to "auto"
        self.server = "telnetmyip.com"  # Set the default CheckMyIP server

    def get(self):  # Primary method to run IP check
        """
        Gets the IP information from the CheckMyIP server.
        Returns:
            dict: A dictionary containing the IP information.
        Raises:
            Exception: If unable to connect to the server.
        """
        if self._af == "auto":  # If we are using an auto address family
            try:  # Try using IPv6
                sock = self._socket.socket(self._socket.AF_INET6,
                                           self._socket.SOCK_STREAM)
                sock.connect((self.server, 23))
            except Exception:  # Fall back to IPv4 if IPv6 fails
                sock = self._socket.socket(self._socket.AF_INET,
                                           self._socket.SOCK_STREAM)
                sock.connect((self.server, 23))
        elif self._af == "ipv6":  # If we are using the IPv6 address family
            sock = self._socket.socket(self._socket.AF_INET6,
                                       self._socket.SOCK_STREAM)
            sock.connect((self.server, 23))
        elif self._af == "ipv4":  # If we are using the IPv4 address family
            sock = self._socket.socket(self._socket.AF_INET,
                                       self._socket.SOCK_STREAM)
            sock.connect((self.server, 23))
        self._raw_data = sock.recv(1024).decode()
        self._data = self._json.loads(self._raw_data)  # Recieve data from the buffer
        sock.close()  # Close the socket
        return self._data  # Return the JSON data

    def set_family(self, family):  # Method to set the IP address family
        """
        Sets the IP address family for the client.
        Args:
            family (str): The address family to use. Must be one of:
                - "auto" : Try IPv6 first, fall back to IPv4
                - "ipv4" : Use IPv4 only
                - "ipv6" : Use IPv6 only
        Raises:
            Exception: If the provided family is not one of the allowed values.
        """
        allowed = ["auto", "ipv4", "ipv6"]  # Allowed input values
        if family in allowed:
            self._af = family
        else:
            raise Exception("Allowed families are 'auto', 'ipv4', 'ipv6'")


if __name__ == "__main__":
    logging = log_management()  # Instantiate log class
    start()  # Start the server
