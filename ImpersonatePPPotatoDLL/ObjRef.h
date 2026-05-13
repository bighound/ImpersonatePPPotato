#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>
#include <optional>
#include <array>

// Enum ficticio para que compile, ya que no estaba definido en tu código C#
enum class TowerProtocol : uint16_t {
    EPM_PROTOCOL_DNET_NSP = 0x04,
    EPM_PROTOCOL_OSI_TP4 = 0x05,
    EPM_PROTOCOL_OSI_CLNS = 0x06,
    EPM_PROTOCOL_TCP = 0x07,
    EPM_PROTOCOL_UDP = 0x08,
    EPM_PROTOCOL_IP = 0x09,
    EPM_PROTOCOL_NCADG = 0x0a,       // Connectionless RPC
    EPM_PROTOCOL_NCACN = 0x0b,
    EPM_PROTOCOL_NCALRPC = 0x0c,     // Local RPC
    EPM_PROTOCOL_UUID = 0x0d,
    EPM_PROTOCOL_IPX = 0x0e,
    EPM_PROTOCOL_SMB = 0x0f,
    EPM_PROTOCOL_NAMED_PIPE = 0x10,
    EPM_PROTOCOL_NETBIOS = 0x11,
    EPM_PROTOCOL_NETBEUI = 0x12,
    EPM_PROTOCOL_SPX = 0x13,
    EPM_PROTOCOL_NB_IPX = 0x14,      // NetBIOS over IPX
    EPM_PROTOCOL_DSP = 0x16,         // AppleTalk Data Stream Protocol
    EPM_PROTOCOL_DDP = 0x17,         // AppleTalk Data Datagram Protocol
    EPM_PROTOCOL_APPLETALK = 0x18,   // AppleTalk
    EPM_PROTOCOL_VINES_SPP = 0x1a,
    EPM_PROTOCOL_VINES_IPC = 0x1b,   // Inter Process Communication
    EPM_PROTOCOL_STREETTALK = 0x1c,  // Vines Streettalk
    EPM_PROTOCOL_HTTP = 0x1f,
    EPM_PROTOCOL_UNIX_DS = 0x20,     // Unix domain socket
    EPM_PROTOCOL_NULL = 0x21
};

// Estructura auxiliar para replicar el comportamiento de Guid en C#
struct Guid {
    std::array<uint8_t, 16> bytes{};
    
    Guid() = default;
    Guid(const std::vector<uint8_t>& data) {
        if (data.size() >= 16) {
            std::memcpy(bytes.data(), data.data(), 16);
        }
    }
};

// Clase auxiliar para reemplazar BinaryReader y BinaryWriter
class BinaryStream {
private:
    std::vector<uint8_t> buffer;
    size_t position = 0;

public:
    BinaryStream() = default;
    BinaryStream(const std::vector<uint8_t>& data) : buffer(data) {}

    const std::vector<uint8_t>& GetBuffer() const { return buffer; }

    template<typename T>
    T Read() {
        if (position + sizeof(T) > buffer.size()) throw std::out_of_range("Fin del stream alcanzado");
        T value;
        std::memcpy(&value, buffer.data() + position, sizeof(T));
        position += sizeof(T);
        return value;
    }

    std::vector<uint8_t> ReadBytes(size_t count) {
        if (position + count > buffer.size()) throw std::out_of_range("Fin del stream alcanzado");
        std::vector<uint8_t> data(buffer.begin() + position, buffer.begin() + position + count);
        position += count;
        return data;
    }

    template<typename T>
    void Write(T value) {
        const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&value);
        buffer.insert(buffer.end(), ptr, ptr + sizeof(T));
    }

    void WriteBytes(const std::vector<uint8_t>& data) {
        buffer.insert(buffer.end(), data.begin(), data.end());
    }
    
    void WriteBytes(const std::array<uint8_t, 16>& data) {
        buffer.insert(buffer.end(), data.begin(), data.end());
    }
};

class ObjRef {
public:
    enum class Type : uint32_t {
        Standard = 0x1,
        Handler = 0x2,
        Custom = 0x4
    };

    static const uint32_t Signature = 0x574f454d;

    // --- CLASES ANIDADAS ---
    // Deben definirse antes de ser usadas en C++

    class SecurityBinding {
    public:
        const uint16_t AuthnSvc;
        const uint16_t AuthzSvc;
        const std::wstring PrincipalName;

        SecurityBinding(uint16_t authnSvc, uint16_t authzSvc, std::wstring principalName)
            : AuthnSvc(authnSvc), AuthzSvc(authzSvc), PrincipalName(std::move(principalName)) {}

        SecurityBinding(BinaryStream& br) 
            : AuthnSvc(br.Read<uint16_t>()), AuthzSvc(br.Read<uint16_t>()) 
        {
            wchar_t character;
            std::wstring principalName = L"";

            while ((character = br.Read<wchar_t>()) != 0) {
                principalName += character;
            }
            br.Read<wchar_t>(); // El char extra que lee el código C# original
            
            // Const cast trick para inicializar variable const en constructor 
            // alternativamente, se podría usar un método estático o delegar constructores.
            const_cast<std::wstring&>(PrincipalName) = principalName;
        }

        std::vector<uint8_t> GetBytes() const {
            BinaryStream bw;
            bw.Write(AuthnSvc);
            bw.Write(AuthzSvc);

            if (!PrincipalName.empty()) {
                for (wchar_t c : PrincipalName) {
                    bw.Write(c);
                }
            }

            bw.Write(static_cast<wchar_t>(0));
            bw.Write(static_cast<wchar_t>(0));

            return bw.GetBuffer();
        }
    };

    class StringBinding {
    public:
        const TowerProtocol TowerID;
        const std::wstring NetworkAddress;

        StringBinding(TowerProtocol towerID, std::wstring networkAddress)
            : TowerID(towerID), NetworkAddress(std::move(networkAddress)) {}

        StringBinding(BinaryStream& br)
            : TowerID(static_cast<TowerProtocol>(br.Read<uint16_t>()))
        {
            wchar_t character;
            std::wstring networkAddress = L"";

            while ((character = br.Read<wchar_t>()) != 0) {
                networkAddress += character;
            }
            br.Read<wchar_t>();
            
            const_cast<std::wstring&>(NetworkAddress) = networkAddress;
        }

        std::vector<uint8_t> GetBytes() const {
            BinaryStream bw;
            bw.Write(static_cast<uint16_t>(TowerID));
            for (wchar_t c : NetworkAddress) {
                bw.Write(c);
            }
            bw.Write(static_cast<wchar_t>(0));
            bw.Write(static_cast<wchar_t>(0));

            return bw.GetBuffer();
        }
    };

    class DualStringArray {
    private:
        uint16_t NumEntries;
        uint16_t SecurityOffset;
    public:
        const StringBinding StringBindingObj;
        const SecurityBinding SecurityBindingObj;

        DualStringArray(StringBinding stringBinding, SecurityBinding securityBinding)
            : StringBindingObj(std::move(stringBinding)), SecurityBindingObj(std::move(securityBinding)) 
        {
            size_t strLen = StringBindingObj.GetBytes().size();
            size_t secLen = SecurityBindingObj.GetBytes().size();
            NumEntries = static_cast<uint16_t>((strLen + secLen) / 2);
            SecurityOffset = static_cast<uint16_t>(strLen / 2);
        }

        DualStringArray(BinaryStream& br)
            : NumEntries(br.Read<uint16_t>()), 
              SecurityOffset(br.Read<uint16_t>()),
              StringBindingObj(br), 
              SecurityBindingObj(br) {}

        void Save(BinaryStream& bw) const {
            std::vector<uint8_t> stringBindingBytes = StringBindingObj.GetBytes();
            std::vector<uint8_t> securityBindingBytes = SecurityBindingObj.GetBytes();

            bw.Write(static_cast<uint16_t>((stringBindingBytes.size() + securityBindingBytes.size()) / 2));
            bw.Write(static_cast<uint16_t>(stringBindingBytes.size() / 2));
            bw.WriteBytes(stringBindingBytes);
            bw.WriteBytes(securityBindingBytes);
        }
    };

    class Standard {
    public:
        static const uint64_t OxidValue = 0x0703d84a06ec96cc;
        static const uint64_t OidValue = 0x539d029cce31ac;

        uint32_t Flags;
        const uint32_t PublicRefs;
        const uint64_t OXID;
        const uint64_t OID;
        const Guid IPID;
        const DualStringArray DualStringArrayObj;

        Standard(uint32_t flags, uint32_t publicRefs, uint64_t oxid, uint64_t oid, Guid ipid, DualStringArray dualStringArray)
            : Flags(flags), PublicRefs(publicRefs), OXID(oxid), OID(oid), IPID(ipid), DualStringArrayObj(std::move(dualStringArray)) {}

        Standard(BinaryStream& br)
            : Flags(br.Read<uint32_t>()),
              PublicRefs(br.Read<uint32_t>()),
              OXID(br.Read<uint64_t>()),
              OID(br.Read<uint64_t>()),
              IPID(br.ReadBytes(16)),
              DualStringArrayObj(br) {}

        void Save(BinaryStream& bw) const {
            bw.Write(Flags);
            bw.Write(PublicRefs);
            bw.Write(OXID);
            bw.Write(OID);
            bw.WriteBytes(IPID.bytes);
            DualStringArrayObj.Save(bw);
        }
    };

    // --- FIN CLASES ANIDADAS ---

    const Guid GuidObj;
    // Usamos std::optional porque en C# esto puede ser null si no es Type::Standard
    std::optional<Standard> StandardObjRef;

    ObjRef(Guid guid, Standard standardObjRef)
        : GuidObj(guid), StandardObjRef(std::move(standardObjRef)) {}

    ObjRef(const std::vector<uint8_t>& objRefBytes) {
        BinaryStream br(objRefBytes);

        if (br.Read<uint32_t>() != Signature) {
            throw std::invalid_argument("Does not look like an OBJREF stream");
        }

        uint32_t flags = br.Read<uint32_t>();
        const_cast<Guid&>(GuidObj) = Guid(br.ReadBytes(16));

        if (static_cast<Type>(flags) == Type::Standard) {
            StandardObjRef.emplace(br);
        }
    }

    std::vector<uint8_t> GetBytes() const {
        BinaryStream bw;

        bw.Write(Signature);
        bw.Write(static_cast<uint32_t>(1));
        bw.WriteBytes(GuidObj.bytes);

        if (StandardObjRef.has_value()) {
            StandardObjRef->Save(bw);
        }

        return bw.GetBuffer();
    }
};