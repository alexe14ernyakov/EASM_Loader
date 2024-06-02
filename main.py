import os
import psycopg2
import json
import time
from dotenv import load_dotenv


def data_selection(data: dict) -> dict:
    result = {}

    longitude: float = data['location']['longitude']
    latitude: float = data['location']['latitude']
    result['long'] = longitude
    result['lat'] = latitude
    result['city'] = data['location']['city']
    result['location_id'] = (str(longitude) + str(latitude).replace('-', '')).replace('.', '')

    ip: str = data['ip_str']
    try:
        dev_type: str | None = data['devicetype']
    except KeyError:
        dev_type: str | None = None
    try:
        as_number: str | None = data['asn']
    except KeyError:
        as_number: str | None = None
    result['ip'] = ip
    result['provider'] = data['isp']
    result['device_type'] = dev_type
    result['asn'] = as_number

    service_id: str = ip.replace('.', '')
    service_id += str(data['port'])
    if data['transport'] == "tcp":
        service_id += "0"
    elif data['transport'] == "udp":
        service_id += "1"
    result['service_id'] = service_id
    result['port'] = data['port']
    result['os'] = data['os']
    result['protocol'] = data['transport']

    try:
        apps_cpe: list = data['cpe23']

        apps = []
        for cpe in apps_cpe:
            cpe: str = cpe
            wfns: list = cpe.split(":")
            if len(wfns) == 6:
                version: str | None = wfns[-1]
            else:
                version: str | None = None

            app_info = {"cpe": cpe,
                        "name": wfns[4],
                        "vendor": wfns[3],
                        "version": version}
            apps.append(app_info)

        result["apps"]: list = apps
    except KeyError:
        result["apps"]: list = []

    try:
        vulns_data: dict = data['vulns']

        vulns: list = []
        for vuln_cve in list(vulns_data.keys()):
            vuln_info = {"cve": vuln_cve,
                         "cvss": vulns_data[vuln_cve]["cvss"],
                         "descr": vulns_data[vuln_cve]["summary"].replace("'", "`")}
            vulns.append(vuln_info)
        result["vulns"]: list = vulns
    except KeyError:
        result["vulns"]: list = []

    return result


def make_insert(connect: psycopg2.extensions.connection, query: str, fields: tuple) -> None:
    with connect:
        with connect.cursor() as curs:
            try:
                curs.execute(query, fields)
            except psycopg2.errors.UniqueViolation:
                pass
            except Exception as exc:
                print(sample)
                print(str(exc))
                exit(1)


if __name__ == "__main__":
    env_path: str = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_path):
        load_dotenv(env_path)

    db_name: str = os.getenv("DB_NAME")
    db_user: str = os.getenv("DB_USER")
    db_password: str = os.getenv("DB_PASSWORD")
    db_host: str = os.getenv("DB_HOST")
    db_port: str = os.getenv("DB_PORT")
    connection: psycopg2.extensions.connection | None = None
    try:
        connection = psycopg2.connect(database=db_name, user=db_user, password=db_password, host=db_host, port=db_port)
    except Exception as e:
        print('Error connecting to database: ' + str(e))
        exit(1)

    start_time = time.time()

    if connection:
        cursor: psycopg2.extensions.cursor = connection.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS Locations('
                       'location_id bigint NOT NULL,'
                       'city text,'
                       'long numeric(8,5) NOT NULL,'
                       'lat numeric(8,5) NOT NULL,'
                       'PRIMARY KEY (location_id),'
                       'UNIQUE (long, lat)'
                       ');'

                       'CREATE TABLE IF NOT EXISTS Hosts('
                       'ip inet NOT NULL,'
                       'provider text,'
                       'dev_type text,'
                       'asn varchar(16),'
                       'location_id bigint,'
                       'PRIMARY KEY (ip),'
                       'FOREIGN KEY (location_id) REFERENCES Locations(location_id)'
                       ');'

                       'CREATE TABLE IF NOT EXISTS Services('
                       'service_id bigint NOT NULL,'
                       'ip inet NOT NULL,'
                       'port integer NOT NULL,'
                       'os text,'
                       'protocol varchar(3),'
                       'PRIMARY KEY (service_id),'
                       'FOREIGN KEY (ip) REFERENCES Hosts(ip),'
                       'UNIQUE (ip, port, protocol)'
                       ');'

                       'CREATE TABLE IF NOT EXISTS Apps('
                       'cpe text NOT NULL,'
                       'vendor text,'
                       'version text,'
                       'PRIMARY KEY (cpe)'
                       ');'

                       'CREATE TABLE IF NOT EXISTS Vulns('
                       'cve varchar(16) NOT NULL,'
                       'cvss numeric(3, 1),'
                       'descr text,'
                       'PRIMARY KEY(cve)'
                       ');'

                       'CREATE TABLE IF NOT EXISTS Services_Apps('
                       'service_id bigint NOT NULL,'
                       'cpe text NOT NULL,'
                       'FOREIGN KEY (service_id) REFERENCES Services(service_id),'
                       'FOREIGN KEY (cpe) REFERENCES Apps(cpe),'
                       'UNIQUE (service_id, cpe)'
                       ');'

                       'CREATE TABLE IF NOT EXISTS Services_Vulns('
                       'service_id bigint NOT NULL,'
                       'cve varchar(16) NOT NULL,'
                       'FOREIGN KEY (service_id) REFERENCES Services(service_id),'
                       'FOREIGN KEY (cve) REFERENCES Vulns(cve),'
                       'UNIQUE (service_id, cve)'
                       ');')

        connection.commit()

    data_path: str = os.getenv("DATA_PATH")
    data_files: list = os.listdir(data_path)

    for file_name in data_files:
        file_path: str = os.path.join(data_path, file_name)

        with open(file_path) as file:
            file_data: list = json.load(file)
            for record in file_data:
                sample: dict = data_selection(record)

                location_query = "INSERT INTO Locations VALUES (%s, %s, %s, %s)"
                host_query = "INSERT INTO Hosts VALUES (%s, %s, %s, %s, %s)"
                service_query = "INSERT INTO Services VALUES (%s, %s, %s, %s, %s)"

                make_insert(connection, location_query, (sample["location_id"],
                                                         sample["city"],
                                                         sample["long"],
                                                         sample["lat"]))
                make_insert(connection, host_query, (sample["ip"],
                                                     sample["provider"],
                                                     sample["device_type"],
                                                     sample["asn"],
                                                     sample["location_id"]))
                make_insert(connection, service_query, (sample["service_id"],
                                                        sample["ip"],
                                                        sample["port"],
                                                        sample["os"],
                                                        sample["protocol"]))

                for app in sample["apps"]:
                    app_query = "INSERT INTO Apps VALUES (%s, %s, %s)"
                    make_insert(connection, app_query, (app["cpe"],
                                                        app["vendor"],
                                                        app["version"]))

                    sa_query = "INSERT INTO Services_Apps VALUES (%s, %s)"
                    make_insert(connection, sa_query, (sample["service_id"],
                                                       app["cpe"]))

                for vuln in sample["vulns"]:
                    vuln_query = "INSERT INTO Vulns VALUES (%s, %s, %s)"
                    make_insert(connection, vuln_query, (vuln["cve"],
                                                         vuln["cvss"],
                                                         vuln["descr"]))

                    sv_query = "INSERT INTO Services_Vulns VALUES (%s, %s)"
                    make_insert(connection, sv_query, (sample["service_id"],
                                                       vuln["cve"]))

            file.close()
        print("File ", file_name, " has been inserted.")
    connection.close()

    end_time = time.time()
    print(f"Process finished in {end_time - start_time} seconds.")
