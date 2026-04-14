import paramiko
import json
import yaml
import os
import logging


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("audit.log", encoding='utf-8'), 
        logging.StreamHandler() 
    ]
)

def get_data():
    with open('config.yaml', 'r') as f:
        servers = yaml.safe_load(f)['servers']
    with open('rules.json', 'r') as f:
        rules = json.load(f)
    return servers, rules

def run_audit():
    servers, rules = get_data()
    
    for server in servers:
        logging.info(f"проверка сервера: {server['name']} ({server['host']})")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            client.connect(
                hostname=server['host'],
                username=server['username'],
                key_filename=os.path.expanduser(server['key_filename']),
                timeout=10
            )
            
            for rule in rules:
                # 1 Проверка
                stdin, stdout, stderr = client.exec_command(rule['command'])
                result = stdout.read().decode('utf-8').strip()
                
                if rule['expected'].lower() in result.lower():
                    logging.info(f"  [OK] {rule['id']}: {rule['description']}")
                else:
                    logging.warning(f"  [!!] {rule['id']}: ПРОВАЛЕНО (Найдено: '{result}')")
                    
                    # 2 Исправление
                    if 'fix_command' in rule:
                        ans = input(f"Применить фикс '{rule['fix_command']}'? (y/n): ")
                        if ans.lower() == 'y':
                            logging.info(f" Выполнение фикса для {rule['id']}...")
                            f_in, f_out, f_err = client.exec_command(rule['fix_command'])
                            f_out.channel.recv_exit_status() 
                            logging.info(f"Фикс завершен")

            client.close()
        except Exception as e:
            logging.error(f" Ошибка соединения с {server['host']}: {e}")

if __name__ == "__main__":
    run_audit()
