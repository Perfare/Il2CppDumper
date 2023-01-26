import codecs
import json

def deserializeJSON(script_file):
    if script_file is not None:
        f = codecs.open(script_file, "r","utf-8")

        # Reading from file
        data = json.loads(f.read())
        f.close()

        return data

def changeAddressNames(script):
    for i in script['ScriptMethod']:
        addr = i['Address']
        name = i['Name']
        #sig = i['Signature']
        #typesig = i['TypeSignature']

        #print(addr, name)
        doc.setNameAtAddress(addr, name)

    return

def main():
    script_file = doc.askFile('Select script.py', None, None)
    script = deserializeJSON(script_file)
    changeAddressNames(script)

doc = Document.getCurrentDocument()
main()
