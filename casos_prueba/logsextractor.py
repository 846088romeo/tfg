'''
Author: Simona Bernardi
Date: 2-July-2025

This module extracts information from a protocol AnBx specification and from 
the execution traces produced by the corresponding AnBx-Java protocol simulator  and
generates a csv file with the relevant events and a file (.goals) with instantiated goal parameters.
Input files: 
- <protocol>.anbx <------ AnBx specification of <protocol>
- <protocol>_role<ROLE>.txt  <----- execution traces of <protocol> (one for each participant <ROLE>)

Output file:
- <protocol>.csv    <--- synthetized execution traces
- <protocol>.goals  <--- instantiated goal parameters 

Usage:
> python3 logsextractor.py <protocol>
'''


import re
import sys
import os
#from datetime import datetime
from heapq import heapify, heappush, heappop #used for greedy optimal file merge pattern

INPUT_PATH = "./input_files/"
OUTPUT_PATH = "./output_files/"
ANBX_PATH = "./anbx_files/"

class Protocol:

    def __init__(self,filename):
        #Loads the protocol spec. from anbx file
        anbx_path = ANBX_PATH + filename + ".AnBx"
        try:
            with open(anbx_path, 'r') as file:
                lines = file.readlines()
                self.initialize(lines)

        except OSError as e:
            print(f"error: {type(e)}: {anbx_path}")


    def initialize(self,lines):
        self.agents = []
        self.actions = []
        self.goals = []
        in_block = dict({'actions': False, 'goals': False})
        for line in lines:
            line = line.replace('\t', '').replace('\n', '').strip()
            if line.startswith('Protocol:'):
                self.name = line.split()[1]
            elif line.startswith('Agent'):
                self.set_roles(line)
            elif line.startswith('Actions:'):
                in_block['actions'] = True
                step = 0
            elif line.startswith('Goals:'):
                in_block['actions'] = False
                in_block['goals'] = True
            elif in_block['actions'] and line.find('->') != -1:
                self.set_actions(line.strip(),step)
                step+=1
            elif in_block['goals']:
                ok = not line.startswith('#') and \
                    (line.find('secret') != -1 or line.find('authenticates') != -1)
                if ok:
                    self.set_goals(line.strip())

    def set_roles(self,line):
        to_be_removed = ['Agent',' ',';']
        for substr in to_be_removed:
            line = line.replace(substr,'')
        for item in line.split(','):
            self.agents.append(item)

    def set_actions(self,line,step):
        action_pattern = re.compile(r'\[*(\w+)\]*\s+.*->.*\s+\[*(\w+)\]*\s*:\s+(.+)')
        matched = action_pattern.match(line)
        if matched:
            sender, receiver, msg = matched.groups()
            msg = msg.split('#')
            self.actions.append([sender, receiver, msg[0].strip()])

    def set_goals(self,line):
        line = line.split()
        match line[1]:
            case 'authenticates': 
                assets = line[-1].split(',')
                #print(assets)
                self.goals.append([ 'auth', assets, [line[0], line[-3]] ]) # 'auth', asset, [who1, who2]     
            case 'secret':
                who = line[-1].split(',')
                self.goals.append(['secret', [line[0]], who]) # 'secret', asset, who list

    def get_step_and_generator(self,goal):
        generator = ''
        found = False
        i=0
        #print("Goal: ", goal)
        while i < len(self.actions) and not found:
            msg = self.actions[i][2]
            #print("Msg: ", msg)
            if goal[1][0] in msg: #check if the first asset is in the message
                generator = self.actions[i][0] #the sender
                found = True
            i+=1
        step = i-1
        if goal[0] == 'auth':
            found = False
            i = 0
            while i < len(self.actions) and not found:
                sender = self.actions[i][0] 
                if sender == generator:
                    step = i
                    found = True
                i+=1
        
        return step,generator

    def get_name(self):
        return self.name

    def get_roles(self):
        return self.agents

    def get_actions(self):
        return self.actions

    def get_sender(self,step):
        return self.actions[step][0]

    def get_receiver(self,step):
        return self.actions[step][1]

    def get_goals(self):
        return self.goals

    def print_protocol(self):
        print("Name: ", self.get_name())
        print("Roles: ", self.get_roles())
        print("Actions: ", self.get_actions())
        print("Goals:")
        for goal in self.get_goals():
            print(goal)
            step, role = self.get_step_and_generator(goal)
            print("Step when the asset ", goal[1] ," was generated:", step, "Who generated it? ", role)
        print("---------------------------------")

class Event:
    def __init__(self, n_line, timestamp, session, step, act_part, pass_part, action, ev_content):
        self.n_line = n_line
        self.ts = timestamp
        self.session = session
        self.step = step
        self.act_part = act_part
        self.pass_part = pass_part
        self.action = action
        self.ev_content = ev_content
        self.ev_type = ''

    def print_event(self):
        print(self.n_line, ' ', self.ts, ' ', self.session, ' ', self.step, ' ', \
            self.act_part, ' ', self.pass_part, ' ', self.action, ' ', self.ev_content, ' ', self.ev_type)

    def get_event_items(self):
        return  self.ts + ',' + str(self.session) + ',' + str(self.step) + ',' + \
                self.act_part + ',' + self.pass_part + ',' + self.action + ',' + \
                self.ev_content + ',' + self.ev_type + '\n'

class Trace:
    #An execution trace of a participant: the events are ordered
    def __init__(self, filename,prot):
        self.file = filename
        self.prot = prot
        self.roles_alias = dict()
        self.whoamI = ''
        self.sessions = 0
        self.keywords = [['Nonce - DRBG - Value:','generateNumber'], ['AnBx_Params - params:','AnBx_Params'], \
                        ['Sent','sent'], ['Received','received'], #['Encrypted','encrypted'], ['Decrypted','decrypted'], \
                        ['EQ check OK','eq_check'], ['INV check OK','inv_check']]
        self.events = []

    def set_roles_alias(self,content,n_roles):
        #ROLE_A:
        whoamI_pattern = re.compile(r'^ROLE_(\w+):') 
        #[java] Debug [[17:31:17:670]ROLE_B-APPLICATION] - Role: ROLE_A - Alias: alice
        role_alias_pattern = re.compile(r'Role:\s*ROLE_(\w+)\s*-\s*Alias:\s*(\w+).*')  
        n_line = 0 
        while n_line < len(content) and len(self.roles_alias) < n_roles:
            match = whoamI_pattern.search(content[n_line])
            if match:
                self.whoamI = match.group(1)
            else:
                match = role_alias_pattern.search(content[n_line])
                if match:
                    rol = match.group(1)  # Extract the role
                    alias = match.group(2) #Extract the alias
                    self.roles_alias.update({rol:alias}) # Update dictionary
            n_line+=1
        return n_line

    def get_roles_alias(self):
        return self.roles_alias

    def set_sessions(self,content,n_line):
        #[java] Debug [[17:31:40:848]ROLE_A-APPLICATION] - [17:31:40:854]sessions: 2
        sessions_pattern = re.compile(r'sessions:\s+(\d+).*')  
        while n_line < len(content) and self.sessions == 0:
            match = sessions_pattern.search(content[n_line])
            if match:
                self.sessions = int(match.group(1))
            n_line+=1
        return n_line

    def get_sessions(self):
        return self.sessions

    def set_current_session(self,session,content,n_line):
        #[java] Debug [[17:31:40:848]ROLE_A-PROTOCOL] - [17:31:41:344]Session started: 1/2
        session_start_pattern = re.compile(r'Session started:\s+(\d+)/.*') 
        current_session = session
        while n_line < len(content) and current_session == session:
            match = session_start_pattern.search(content[n_line])
            if match:
                current_session = int(match.group(1))  # Extract current session
            n_line+=1
        return current_session, n_line

    def select_event(self,n_line,session,step,line):
        found = False 
        i=0
        while i < len(self.keywords) and not found:
            found = (self.keywords[i][0] in line) 
            i+=1
        found = "hashCode" not in line
        #Select events having one of the keywords
        #print("N line: ", n_line)
        if found:               
            keyword = self.keywords[i-1][0]
            action = self.keywords[i-1][1]
            #Define active participant
            act_part = self.roles_alias[self.whoamI]
            #Define the passive participant
            #print("step:", step)
            match action:
                case 'sent':
                    pass_part = self.roles_alias[self.prot.get_receiver(int(step))]
                case 'received':
                    pass_part = self.roles_alias[self.prot.get_sender(int(step))]
                case _:
                    pass_part = '-'
            #Initially sets the event content, and the timestamp 
            #when available (logs from generated Java code with modified AnBxJ library and ST templates)
            event_pattern = re.match(r'.*'+keyword+'(.+)$', line)
            if event_pattern:
                ev_content = event_pattern.groups()[0].strip()
                #[java] Debug [[17:31:17:670]ROLE_B-NETWORK] - [17:31:41:493]Received <- AnBx_Params [v=[alice, javax.crypto.SealedObject@4590c9c3]]
                #event_pattern_ts = re.match(r'.*\[\[(\d{2}:\d{2}:\d{2}:\d{3})\].+\].+'+keyword+'(.+)$', line)
                event_pattern_ts = re.match(r'.*\[(\d{2}:\d{2}:\d{2}:\d{3})\]'+keyword+'(.+)$', line)
                if event_pattern_ts:
                    timestamp = event_pattern_ts.groups()[0]
                else:
                    event_pattern_ts = re.match(r'.*\[\[(\d{2}:\d{2}:\d{2}:\d{3})\].+\].+'+keyword+'(.+)$', line)
                    if event_pattern_ts:
                        timestamp = event_pattern_ts.groups()[0]
                    else:
                        timestamp = '00:00:00:000'
                #print("Event content: ", ev_content)
                self.events.append(Event(n_line,timestamp,session,step,act_part,pass_part,action,ev_content))  

        return line

    def get_events(self):
        return self.events

    def print_trace(self):
        print("Trace events: ")
        for ev in self.events:
            ev.print_event()

    # Process steps in session 
    def process_steps(self,content,n_line,session):
        #[java] Debug [[17:31:40:848]ROLE_A-PROTOCOL] - [17:31:41:856]Session completed: 1/2
        session_completed_pattern = re.compile(r'Session completed:\s+(\d+)/.*') 
        in_session = True
        processed_lines = []
        step_number = None
        
        while n_line < len(content) and in_session:
            match = session_completed_pattern.search(content[n_line]) 
            if match:
                in_session = False
                print("Session ", match.group(1), " completed")
            else:
                # Extract the step number
                #[java] Debug [[17:31:40:848]ROLE_A-PROTOCOL] - AndrewSecureRPC_AttackTrace_active - ROLE_A - STEP_0
                step_pattern = re.compile(r'STEP_(\d+).*')
                match = step_pattern.search(content[n_line])
                # Process the step number
                if match:
                    step = match.group(1)
                # Filter and process relevant events 
                elif in_session and step is not None:
                    line = self.select_event(n_line,session,step,content[n_line])
            n_line+=1

    
    def filtering(self):
        #Filter the trace 
        input_path = INPUT_PATH + self.file
        print("Reading file: ", input_path)
        with open(input_path, 'r') as file:
            content = file.readlines()
        
        n_roles = len(self.prot.get_roles())
        n_line = self.set_roles_alias(content,n_roles)
        print("whoamI: ", self.whoamI)
        print("Current line", n_line, "--->Roles and alias: ", self.roles_alias)

        n_line = self.set_sessions(content,n_line)
        print("Current line", n_line, "--->Sessions: ",self.sessions)
            
        session=0
        while session < self.sessions:
            session, n_line = self.set_current_session(session,content,n_line)
            print("Current line: ",n_line,"---->Current session: ", session)    
            self.process_steps(content,n_line,session)

class Log:
    def __init__(self, traces):
        self.traces = traces
        #print(traces)
        self.roles_alias = self.traces[0].get_roles_alias()
        self.assets = dict()
        self.sessions = self.traces[0].get_sessions()
        self.prot = self.traces[0].prot
        self.valueID = -1
        self.crypto_byte_arrays_dict = dict() #  mapping  crypto byte array values to unique identifiers
        self.events = []

    def check_consistency(self):
        #Minimum check whether the set of participants is the same and the number sessions is the same
        ok = True
        i = 1
        while(i < len(self.traces) and ok):
            if  self.traces[i].get_roles_alias() != self.roles_alias or self.traces[i].get_sessions() != self.sessions:
                ok = False
            i+=1
        return ok
    
    def merge_events(self,events1,events2):
        #Merge two ordered event lists
        i = 0
        j = 0
        merged = []
        while(i < len(events1) and j < len(events2)):
            #order criterion: session
            if int(events1[i].session) < int(events2[j].session): 
                merged.append(events1[i])
                i+=1
            elif int(events1[i].session) > int(events2[j].session): 
                merged.append(events2[j])
                j+=1
            else:
                #order criterion: same session, step
                if int(events1[i].step) < int(events2[j].step):
                    merged.append(events1[i])
                    i+=1
                elif int(events1[i].step) > int(events2[j].step):
                    merged.append(events2[j])
                    j+=1
                else:
                    #order criterion: same session, same step, sender first
                    step = events1[i].step
                    sender = self.roles_alias[self.prot.get_sender(int(step))]
                    if events1[i].act_part == sender: #active participant is the sender
                        merged.append(events1[i])
                        i+=1
                    else:
                        merged.append(events2[j])
                        j+=1
        #Append the remaining events
        while(i < len(events1)):
            merged.append(events1[i])
            i+=1
        while(j < len(events2)):
            merged.append(events2[j])
            j+=1   
        return merged      

    def merge_traces(self):
        #Merge all the traces together (greedy)
        #Sort traces according to the number of events
        self.traces.sort(key=lambda x: len(x.events))
        # Creating empty heap 
        heap = [] 
        i = 0 #counter needed for cases of node with the same length
        for tr in traces:
            #print("trace length: ", len(tr.events))
            heappush(heap,(len(tr.events), i, tr.get_events())) 
            i+=1        

        while len(heap) > 1:
            ev1 = heappop(heap)
            ev2 = heappop(heap) 
            merged = self.merge_events(ev1[2],ev2[2])
            heappush(heap, (len(merged), i, merged))
            i+=1

        self.events = heappop(heap)[2]

    def print_log(self):
        print("Log events: ")
        for ev in self.events:
            ev.print_event()

    def save_goal_instantiation(self,filename):
        #Format: DLTL like syntax
        with open(filename, 'w') as file:
            #Role instantiation
            for key, value in self.roles_alias.items():
                file.write(f"_SET ?{key} '{value}'\n") 
            #Goal specification and asset instantiation          
            for goal in self.prot.get_goals():
                file.write(";GOAL ")
                #Goal: secret/auth
                file.write(f"{goal[0]}:[")
                #What? Assets
                for asset in goal[1]:
                    file.write(f"?{asset}")
                file.write("],[")
                #Who? Involved roles
                for g in range(len(goal[2])-1):
                    file.write(f"?{goal[2][g]},")
                file.write(f"?{goal[2][-1]}]\n")  
                #Asset instantiation  
                #Assumed only one asset, it needs to be revised in case of more assets!
                assets_instances = self.assets[goal[1][0]]
                file.write(f"_SET ?{goal[1][0]} ")
                for i in range(len(assets_instances)-1):
                    file.write(f"'{assets_instances[i][1]}',")
                file.write(f"'{assets_instances[-1][1]}'\n")

    def save_log(self,filename):     
        with open(filename, 'w') as file:
            file.write("#timestamp,session,step,active_part,passive_part,action,msg_content,msg_type\n")
            for ev in self.events:
                file.write(f"{ev.get_event_items()}")

    def get_event_type(self,content):
        type = {'AnBx_Params': 'anbxj.AnBx_Params',
                'Crypto_SealedPair' : 'anbxj.Crypto_SealedPair', 
                'Crypto_ByteArray ' : 'anbxj.Crypto_ByteArray', 
                'javax.crypto.SealedObject@': 'javax.crypto.SealedObject',
                'java.security.SignedObject@' : 'java.security.SignedObject'
                }
        i=0
        found = False
        ev_type = 'string'
        keys = list(type)
        while i < len(keys) and not found:
            found = type[keys[i]] in content
            i+=1
        if found:
            ev_type = type[keys[i-1]]
        return ev_type

    def format_events(self):        
        for ev in self.events:
            #Get event type 
            match ev.action:
                case 'received' | 'sent':
                    ev.ev_type = self.get_event_type(ev.ev_content)
                case 'generateNumber':
                    ev.ev_type = 'anbxj.Crypto_ByteArray'
                case 'AnBx_Params':
                    match_pattern = re.match(r'-\s(.+?)\s-\s(.+?)$', ev.ev_content)
                    if match_pattern:
                        ev.ev_type, ev.ev_content = match_pattern.groups()
                    else:
                        ev.ev_type = 'anbxj.AnBx_Params'
                case 'eq_check':
                    match_pattern = re.match(r'-\s(.+?)\s-\s(.+)=\s.+$', ev.ev_content)
                    if match_pattern:
                        ev.ev_type, ev.ev_content = match_pattern.groups()
                    else:
                        match_pattern = re.match(r'-\s(.+?)\s-\s.+$', ev.ev_content)
                        if match_pattern:
                            ev.ev_type = match_pattern.groups()[0]
                            ev.ev_content = ''                     
                case 'inv_check':
                    match_pattern = re.match(r'-\s(.+?)\s-\s(.+)$', ev.ev_content)
                    if match_pattern:
                        ev.ev_type, ev.ev_content = match_pattern.groups()
            
            #Replace crypto byte arrays with identifiers
            crypto_byte_arrays = re.findall(r'bytearray=(\[[0-9-].*?\])', ev.ev_content)
            if not crypto_byte_arrays:
                crypto_byte_arrays = re.findall(r'(\[[0-9-].*?\])', ev.ev_content)
            for cb in crypto_byte_arrays:
                cb = cb.strip()
                if cb not in self.crypto_byte_arrays_dict:
                    self.valueID=self.valueID+1
                    identifier = 'X' + str(self.valueID)
                    self.crypto_byte_arrays_dict.update({cb: identifier})
                ev.ev_content = ev.ev_content.replace(cb, self.crypto_byte_arrays_dict[cb]) 
            

            #print("Event content - before clean content", ev.ev_content)

            #Clean content
            to_be_removed = ['Crypto_ByteArray', 'bytearray=', 'javax.crypto.spec.SecretKeySpec', \
                        'AnBx_Params', 'javax.crypto.SealedObject','[v=','[',']','<-', '->', \
                        'Crypto_SealedPair{sealedKey=','sealedMessage=',', cipherScheme=\'AES\'}', 
                        'Sun RSA public key, 2048 bits','java.security.SignedObject',' ']
            for substring in to_be_removed:
                ev.ev_content = ev.ev_content.replace(substring,'')
            ev.ev_content = ev.ev_content.replace(',',';')
            
            #print("Event content - after clean content", ev.ev_content)

        #Replace sealed objects
        sealed_obj_pattern = re.compile(r'.*?(@[0-9a-f]+).*?')
        for i in range(len(self.events)):
            sealed_obj = sealed_obj_pattern.match(self.events[i].ev_content)
            if sealed_obj:
                match self.events[i].action:
                    case 'received' :
                        self.events[i].ev_content = self.events[i-1].ev_content
                    case 'sent':
                        if self.events[i-1].action == 'AnBx_Params':
                            self.events[i].ev_content = self.events[i-1].ev_content
                    case 'AnBx_Params':
                            if self.events[i-1].action == 'AnBx_Params':
                                #self.events[i].ev_content = self.events[i].ev_content.replace(sealed_obj.groups()[0],'')
                                self.events[i].ev_content += (';' + self.events[i-1].ev_content)

    def set_assets(self):
        #Mapping of the asset instances to the assets in the protocol spec
        #In case of more than one goal this code need to be checked/revised
        for goal in self.prot.get_goals(): 
            step, generator = self.prot.get_step_and_generator(goal)
            generator = self.roles_alias[generator]
            print("step-generator", step,generator)
            asset_instances = []
            current_session = 0
            #candidate_event = False
            for ev in self.events:
                if ev.session != current_session:
                    #Not completely checked
                    if ev.session == current_session + 2:
                        #Asset not found in previous session
                        current_session += 1
                        asset_instances.append([current_session,''])
                    
                    candidate_event = ( int(ev.step) == step and ev.act_part == generator and 
                                        (ev.action == 'generateNumber' or ev.action == 'inv_check')
                                        )

                    if candidate_event:
                        asset_instances.append([ev.session,ev.ev_content])
                        current_session = ev.session
            if ev.session == current_session + 1:
                #Asset not found in the last session
                asset_instances.append([current_session,''])

            self.assets.update({goal[1][0]: asset_instances})


            
################################################################################################################

def check_preconditions(args):
    # Checking invocation parameters
    if len(args) != 2:
        print("Usage: python3 logsextractor.py <protocol_name>")
        exit(85)
 
    # Preventing execution error 
    dir_not_exist = not os.path.isdir(ANBX_PATH) or \
                    not os.path.isdir(INPUT_PATH) or \
                    not os.path.isdir(OUTPUT_PATH)

    if dir_not_exist:
        print("The following directories are needed:")
        print(ANBX_PATH)
        print(INPUT_PATH)
        print(OUTPUT_PATH)
        exit(1)
 
if __name__ == '__main__':
    '''
    args:
    sys.arg[1]: name of the protocol (anbx file with the same name of the protocol)
    '''
    check_preconditions(sys.argv)

    print("Reading Protocol anbx file....")
    p = Protocol(sys.argv[1])
    p.print_protocol()

    traces = []
    print("Reading participant traces and selecting relevant events ....")
    for file in os.listdir(INPUT_PATH):
        prefix = sys.argv[1] + '_role'          
        if file.startswith(prefix):     
            print("File: ", file, "Prefix: ", prefix)      
            trace = Trace(file,p)
            trace.filtering()
            traces.append(trace)

    #Assume there are the traces
    print("Generating log...............................................")
    log = Log(traces)
    if not log.check_consistency():
        print("Problem with traces (different set of participants or number of sessions")

    log.merge_traces()
    log.format_events()
    log.set_assets()

    filename = OUTPUT_PATH + sys.argv[1] + '.csv'
    print("Save log in ", filename + ".............................")
    log.save_log(filename)

    filename = OUTPUT_PATH + sys.argv[1] + '.goals'
    print("Save goal parameter instantiation in ", filename + ".............................")
    log.save_goal_instantiation(filename)
