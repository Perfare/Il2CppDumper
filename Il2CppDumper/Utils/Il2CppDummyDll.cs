using System;
using System.Reflection;
using Mono.Cecil;
using Mono.Cecil.Cil;
using FieldAttributes = Mono.Cecil.FieldAttributes;
using MethodAttributes = Mono.Cecil.MethodAttributes;
using TypeAttributes = Mono.Cecil.TypeAttributes;

namespace Il2CppDumper
{
    internal static class Il2CppDummyDll
    {
        private static Type attributeType;
        private static ConstructorInfo attributeConstructor;

        static Il2CppDummyDll()
        {
            attributeType = typeof(Attribute);
            attributeConstructor = attributeType.GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance)[0];
        }

        public static AssemblyDefinition Create()
        {
            var assemblyName = new AssemblyNameDefinition("Il2CppDummyDll", new Version("3.7.1.6"));
            var assemblyDefinition = AssemblyDefinition.CreateAssembly(assemblyName, "Il2CppDummyDll.dll", ModuleKind.Dll);
            var stringTypeReference = assemblyDefinition.MainModule.TypeSystem.String;
            var attributeTypeReference = assemblyDefinition.MainModule.ImportReference(attributeType);
            var types = assemblyDefinition.MainModule.Types;
            var namespaceName = "Il2CppDummyDll";
            var addressAttribute = new TypeDefinition(namespaceName, "AddressAttribute", (TypeAttributes)0x100001, attributeTypeReference);
            addressAttribute.Fields.Add(new FieldDefinition("RVA", FieldAttributes.Public, stringTypeReference));
            addressAttribute.Fields.Add(new FieldDefinition("Offset", FieldAttributes.Public, stringTypeReference));
            addressAttribute.Fields.Add(new FieldDefinition("VA", FieldAttributes.Public, stringTypeReference));
            addressAttribute.Fields.Add(new FieldDefinition("Slot", FieldAttributes.Public, stringTypeReference));
            types.Add(addressAttribute);
            CreateDefaultConstructor(addressAttribute);
            var fieldOffsetAttribute = new TypeDefinition(namespaceName, "FieldOffsetAttribute", (TypeAttributes)0x100001, attributeTypeReference);
            fieldOffsetAttribute.Fields.Add(new FieldDefinition("Offset", FieldAttributes.Public, stringTypeReference));
            types.Add(fieldOffsetAttribute);
            CreateDefaultConstructor(fieldOffsetAttribute);
            var attributeAttribute = new TypeDefinition(namespaceName, "AttributeAttribute", (TypeAttributes)0x100001, attributeTypeReference);
            attributeAttribute.Fields.Add(new FieldDefinition("Name", FieldAttributes.Public, stringTypeReference));
            attributeAttribute.Fields.Add(new FieldDefinition("RVA", FieldAttributes.Public, stringTypeReference));
            attributeAttribute.Fields.Add(new FieldDefinition("Offset", FieldAttributes.Public, stringTypeReference));
            types.Add(attributeAttribute);
            CreateDefaultConstructor(attributeAttribute);
            var metadataOffsetAttribute = new TypeDefinition(namespaceName, "MetadataOffsetAttribute", (TypeAttributes)0x100001, attributeTypeReference);
            metadataOffsetAttribute.Fields.Add(new FieldDefinition("Offset", FieldAttributes.Public, stringTypeReference));
            types.Add(metadataOffsetAttribute);
            CreateDefaultConstructor(metadataOffsetAttribute);
            var tokenAttribute = new TypeDefinition(namespaceName, "TokenAttribute", (TypeAttributes)0x100001, attributeTypeReference);
            tokenAttribute.Fields.Add(new FieldDefinition("Token", FieldAttributes.Public, stringTypeReference));
            types.Add(tokenAttribute);
            CreateDefaultConstructor(tokenAttribute);
            return assemblyDefinition;
        }

        private static void CreateDefaultConstructor(TypeDefinition typeDefinition)
        {
            var module = typeDefinition.Module;
            var defaultConstructor = new MethodDefinition(".ctor",
                MethodAttributes.Public | MethodAttributes.HideBySig |
                MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
                module.ImportReference(typeof(void)));
            var processor = defaultConstructor.Body.GetILProcessor();
            processor.Emit(OpCodes.Ldarg_0);
            processor.Emit(OpCodes.Call, module.ImportReference(attributeConstructor));
            processor.Emit(OpCodes.Ret);
            typeDefinition.Methods.Add(defaultConstructor);
        }
    }
}
