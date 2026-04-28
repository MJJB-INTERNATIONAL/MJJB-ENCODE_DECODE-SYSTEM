// MJJB Encode/Decode Server — Android NDK (POSIX)
// Cipher core is byte-for-byte identical to the Windows version.

#include <jni.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <map>
#include <array>
#include <stdexcept>
#include <android/log.h>

#define TAG "MJJB"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ── Stop flag ────────────────────────────────────────────────────────────────
static volatile int g_stop  = 0;
static int          g_srv   = -1;

// ═══════════════════════════════════════════════════════════════════════════
//  CIPHER CORE  (identical to Windows version)
// ═══════════════════════════════════════════════════════════════════════════

static const uint64_t BLOCK_SIZE = 65536;
static const size_t   CHUNK_SIZE = 4 * 1024 * 1024;

struct KeyParams {
    std::vector<uint8_t> xor_stream;
    uint8_t seed;
    int shuffle_mult;
    int shuffle_off;
};

static uint64_t key_digest(const std::string& key) {
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : key) { h ^= c; h *= 1099511628211ULL; }
    return h;
}

static int next_coprime(int start, int n) {
    if (n <= 1) return 1;
    auto gcd = [](int a, int b) -> int { while(b){ int t=b;b=a%b;a=t; } return a; };
    for (int i = (start > 1 ? start : 2); ; i++)
        if (gcd(i, n) == 1) return i;
}

static inline uint32_t rotl32(uint32_t x, int r) { return (x<<r)|(x>>(32-r)); }

static std::vector<uint8_t> build_xor_stream(const std::string& key) {
    std::vector<uint8_t> stream(32, 0);
    uint64_t h1 = key_digest(key);
    uint64_t h2 = key_digest(key + "_MJJB");
    std::array<uint32_t,8> st = {
        (uint32_t)(h1),(uint32_t)(h1>>32),
        (uint32_t)(h2),(uint32_t)(h2>>32),
        0x61707865u,0x3320646eu,0x79622d32u,0x6b206574u
    };
    for (int r=0;r<10;r++){
        st[0]+=st[1];st[3]^=st[0];st[3]=rotl32(st[3],16);
        st[2]+=st[3];st[1]^=st[2];st[1]=rotl32(st[1],12);
        st[0]+=st[1];st[3]^=st[0];st[3]=rotl32(st[3], 8);
        st[2]+=st[3];st[1]^=st[2];st[1]=rotl32(st[1], 7);
    }
    for (int i=0;i<8;i++){
        stream[i*4+0]=(uint8_t)(st[i]&0xFF);
        stream[i*4+1]=(uint8_t)((st[i]>>8)&0xFF);
        stream[i*4+2]=(uint8_t)((st[i]>>16)&0xFF);
        stream[i*4+3]=(uint8_t)((st[i]>>24)&0xFF);
    }
    return stream;
}

static KeyParams derive_params(const std::string& key, uint64_t padded_size) {
    KeyParams p;
    uint64_t digest = key_digest(key);
    p.xor_stream    = build_xor_stream(key);
    p.seed          = (uint8_t)(digest & 0xFF);
    uint64_t nb     = padded_size / BLOCK_SIZE;
    int n           = (int)((nb > 1) ? nb : 1);
    p.shuffle_off   = (int)((digest >> 8)  % (uint64_t)n);
    p.shuffle_mult  = next_coprime((int)((digest >> 16) % (uint64_t)n) + 2, n);
    return p;
}

static void do_block_shuffle_inplace(uint8_t* data, uint64_t padded_size,
                                     const KeyParams& p, bool forward) {
    uint64_t num_blocks = padded_size / BLOCK_SIZE;
    if (num_blocks <= 1) return;
    uint64_t mult = (uint64_t)p.shuffle_mult;
    uint64_t off  = (uint64_t)p.shuffle_off % num_blocks;
    auto gcd64 = [](uint64_t a, uint64_t b) -> uint64_t {
        while(b){ uint64_t t=b;b=a%b;a=t; } return a;
    };
    while (gcd64(mult, num_blocks) != 1) mult++;
    std::vector<uint32_t> perm(num_blocks);
    if (forward) {
        for (uint64_t i=0;i<num_blocks;i++)
            perm[(i*mult+off)%num_blocks]=(uint32_t)i;
    } else {
        for (uint64_t i=0;i<num_blocks;i++)
            perm[i]=(uint32_t)((i*mult+off)%num_blocks);
    }
    std::vector<uint8_t> tmp(BLOCK_SIZE);
    std::vector<bool> visited(num_blocks,false);
    for (uint64_t start=0;start<num_blocks;start++){
        if (visited[start]||perm[start]==(uint32_t)start){visited[start]=true;continue;}
        memcpy(tmp.data(),data+start*BLOCK_SIZE,BLOCK_SIZE);
        uint64_t cur=start;
        while(true){
            uint64_t nxt=perm[cur];
            visited[cur]=true;
            if(nxt==start){memcpy(data+cur*BLOCK_SIZE,tmp.data(),BLOCK_SIZE);break;}
            memcpy(data+cur*BLOCK_SIZE,data+nxt*BLOCK_SIZE,BLOCK_SIZE);
            cur=nxt;
        }
    }
}

static void stage_xor_inplace(uint8_t* data, uint64_t sz, const KeyParams& p) {
    uint8_t prev=p.seed; int ksz=(int)p.xor_stream.size();
    for (uint64_t i=0;i<sz;i++){
        uint8_t mix=p.xor_stream[i%ksz];
        uint8_t f=(prev<<1)|(prev>>7);
        data[i]^=f^mix; prev=data[i];
    }
}
static void stage_xor_decode_inplace(uint8_t* data, uint64_t sz, const KeyParams& p) {
    uint8_t prev=p.seed; int ksz=(int)p.xor_stream.size();
    for (uint64_t i=0;i<sz;i++){
        uint8_t cipher=data[i];
        uint8_t mix=p.xor_stream[i%ksz];
        uint8_t f=(prev<<1)|(prev>>7);
        data[i]^=f^mix; prev=cipher;
    }
}
static void stage_chain_encode_inplace(uint8_t* data, uint64_t sz, const KeyParams& p) {
    uint8_t prev=p.seed; int ksz=(int)p.xor_stream.size();
    uint64_t done=0;
    while(done<sz){
        uint64_t chunk=std::min((uint64_t)CHUNK_SIZE,sz-done);
        for(uint64_t i=0;i<chunk;i++){
            uint64_t idx=done+i;
            data[idx]^=prev^p.xor_stream[idx%(uint64_t)ksz];
            prev=data[idx];
        }
        done+=chunk;
    }
}
static void stage_chain_decode_inplace(uint8_t* data, uint64_t sz, const KeyParams& p) {
    uint8_t prev=p.seed; int ksz=(int)p.xor_stream.size();
    uint64_t done=0;
    while(done<sz){
        uint64_t chunk=std::min((uint64_t)CHUNK_SIZE,sz-done);
        for(uint64_t i=0;i<chunk;i++){
            uint64_t idx=done+i;
            uint8_t cipher=data[idx];
            data[idx]^=prev^p.xor_stream[idx%(uint64_t)ksz];
            prev=cipher;
        }
        done+=chunk;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  POSIX MAPPED BUFFER (replaces Windows MappedFile)
// ═══════════════════════════════════════════════════════════════════════════

struct MappedBuf {
    uint8_t* ptr  = nullptr;
    size_t   size = 0;

    bool create(uint64_t sz) {
        size = (size_t)sz;
        ptr  = (uint8_t*)mmap(nullptr, size, PROT_READ|PROT_WRITE,
                               MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        return ptr != MAP_FAILED;
    }
    void close() {
        if (ptr && ptr != MAP_FAILED) { munmap(ptr, size); ptr=nullptr; }
    }
    ~MappedBuf() { close(); }
    MappedBuf() = default;
    MappedBuf(const MappedBuf&) = delete;
    MappedBuf& operator=(const MappedBuf&) = delete;
};

// ═══════════════════════════════════════════════════════════════════════════
//  PIPELINE
// ═══════════════════════════════════════════════════════════════════════════

static std::vector<std::string> parse_stages(const std::string& s) {
    std::vector<std::string> stages;
    std::stringstream ss(s); std::string tok;
    while(std::getline(ss,tok,',')){
        tok.erase(0,tok.find_first_not_of(" \t\r\n"));
        if(!tok.empty()&&tok.back()=='\r') tok.pop_back();
        tok.erase(tok.find_last_not_of(" \t\r\n")+1);
        if(!tok.empty()) stages.push_back(tok);
    }
    if(stages.size()!=3) throw std::runtime_error("INVALID STAGE ORDER");
    return stages;
}

static void run_cipher(
    const uint8_t* in_data, uint64_t in_size,
    const std::array<std::string,3>& keys,
    const std::string& stage_order_str,
    const std::string& mode,
    MappedBuf& out_buf, uint64_t& out_size)
{
    auto stages = parse_stages(stage_order_str);
    bool enc    = (mode == "encode");

    if (enc) {
        uint64_t original_size = in_size;
        uint64_t num_blocks = (original_size+BLOCK_SIZE-1)/BLOCK_SIZE;
        if(num_blocks==0) num_blocks=1;
        uint64_t padded_size = num_blocks*BLOCK_SIZE;
        uint64_t total_out   = 8+padded_size;

        if(!out_buf.create(total_out)) throw std::runtime_error("mmap failed");

        uint8_t* p = out_buf.ptr;
        for(int i=0;i<8;i++) p[i]=(uint8_t)((original_size>>(i*8))&0xFF);
        memcpy(p+8, in_data, (size_t)original_size);

        uint8_t* buf=p+8;
        std::map<std::string,KeyParams> kp;
        kp["SHUFFLE"]=derive_params(keys[0],padded_size);
        kp["XOR"]    =derive_params(keys[1],padded_size);
        kp["CHAIN"]  =derive_params(keys[2],padded_size);

        for(const auto& s:stages){
            const KeyParams& kpi=kp.at(s);
            if      (s=="SHUFFLE") do_block_shuffle_inplace(buf,padded_size,kpi,true);
            else if (s=="XOR")     stage_xor_inplace(buf,padded_size,kpi);
            else if (s=="CHAIN")   stage_chain_encode_inplace(buf,padded_size,kpi);
        }
        out_size=total_out;

    } else {
        if(in_size<8) throw std::runtime_error("Invalid encoded data");
        uint64_t original_size=0;
        for(int i=0;i<8;i++) original_size|=((uint64_t)in_data[i])<<(i*8);
        uint64_t padded_size=in_size-8;
        if(padded_size==0||padded_size%BLOCK_SIZE!=0)
            throw std::runtime_error("Not block-aligned");

        if(!out_buf.create(padded_size)) throw std::runtime_error("mmap failed");
        memcpy(out_buf.ptr, in_data+8, (size_t)padded_size);

        std::map<std::string,KeyParams> kp;
        kp["SHUFFLE"]=derive_params(keys[0],padded_size);
        kp["XOR"]    =derive_params(keys[1],padded_size);
        kp["CHAIN"]  =derive_params(keys[2],padded_size);

        std::vector<std::string> rev(stages.rbegin(),stages.rend());
        for(const auto& s:rev){
            const KeyParams& kpi=kp.at(s);
            if      (s=="SHUFFLE") do_block_shuffle_inplace(out_buf.ptr,padded_size,kpi,false);
            else if (s=="XOR")     stage_xor_decode_inplace(out_buf.ptr,padded_size,kpi);
            else if (s=="CHAIN")   stage_chain_decode_inplace(out_buf.ptr,padded_size,kpi);
        }
        out_size=original_size;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  HTTP SERVER (POSIX)
// ═══════════════════════════════════════════════════════════════════════════

static std::string to_lower(std::string s){
    std::transform(s.begin(),s.end(),s.begin(),::tolower); return s;
}
static std::string str_trim(const std::string& s){
    size_t a=s.find_first_not_of(" \t\r\n");
    if(a==std::string::npos) return "";
    size_t b=s.find_last_not_of(" \t\r\n");
    return s.substr(a,b-a+1);
}

struct MultipartField {
    std::string name,filename;
    const uint8_t* data_ptr=nullptr;
    uint64_t data_size=0;
};

static std::vector<MultipartField> parse_multipart(
    const uint8_t* bdata, uint64_t bsize, const std::string& boundary)
{
    std::vector<MultipartField> fields;
    std::string delim="--"+boundary;
    std::string end_marker="--"+boundary+"--";

    auto find_seq=[&](const std::string& needle, uint64_t start)->uint64_t{
        if(needle.size()>bsize) return UINT64_MAX;
        uint64_t lim=bsize-needle.size();
        for(uint64_t i=start;i<=lim;i++)
            if(memcmp(bdata+i,needle.data(),needle.size())==0) return i;
        return UINT64_MAX;
    };

    uint64_t pos=find_seq(delim,0);
    if(pos==UINT64_MAX) return fields;

    while(true){
        uint64_t part_start=pos+delim.size();
        if(part_start+1<bsize&&bdata[part_start]=='\r'&&bdata[part_start+1]=='\n') part_start+=2;
        else if(part_start<bsize&&bdata[part_start]=='\n') part_start+=1;
        else break;

        uint64_t next_delim=find_seq(delim,part_start);
        if(next_delim==UINT64_MAX) break;

        uint64_t part_end=next_delim;
        if(part_end>=2&&bdata[part_end-2]=='\r'&&bdata[part_end-1]=='\n') part_end-=2;
        else if(part_end>=1&&bdata[part_end-1]=='\n') part_end-=1;

        MultipartField field;
        uint64_t header_end=UINT64_MAX;
        for(uint64_t i=part_start;i+1<part_end;i++){
            if(bdata[i]=='\r'&&bdata[i+1]=='\n'&&i+3<part_end&&bdata[i+2]=='\r'&&bdata[i+3]=='\n')
                {header_end=i+4;break;}
            if(bdata[i]=='\n'&&bdata[i+1]=='\n'){header_end=i+2;break;}
        }
        if(header_end==UINT64_MAX){pos=next_delim;continue;}

        std::string hdr_str((char*)bdata+part_start,(char*)bdata+header_end);
        std::istringstream hss(hdr_str); std::string hline;
        while(std::getline(hss,hline)){
            if(!hline.empty()&&hline.back()=='\r') hline.pop_back();
            if(to_lower(hline).find("content-disposition")!=std::string::npos){
                auto np=hline.find("name=\"");
                if(np!=std::string::npos){np+=6;auto ne=hline.find('"',np);field.name=hline.substr(np,ne-np);}
                auto fp=hline.find("filename=\"");
                if(fp!=std::string::npos){fp+=10;auto fe=hline.find('"',fp);field.filename=hline.substr(fp,fe-fp);}
            }
        }
        field.data_ptr=bdata+header_end;
        field.data_size=part_end-header_end;
        fields.push_back(field);
        pos=next_delim;
        if(find_seq(end_marker,pos)==pos) break;
    }
    return fields;
}

static void send_all(int sock, const char* data, size_t len){
    size_t sent=0;
    while(sent<len){
        ssize_t r=send(sock,data+sent,(int)(len-sent),0);
        if(r<=0) break;
        sent+=r;
    }
}

static void send_text(int sock, int code, const char* status, const std::string& body){
    std::string hdr="HTTP/1.1 "+std::to_string(code)+" "+status+"\r\n"
        "Content-Type: text/plain\r\nContent-Length: "+std::to_string(body.size())+"\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "Connection: close\r\n\r\n";
    send_all(sock,hdr.c_str(),hdr.size());
    send_all(sock,body.c_str(),body.size());
}

static void handle_client(int sock){
    // Read headers
    std::string raw; raw.reserve(4096);
    char ch[1];
    while(true){
        int r=recv(sock,ch,1,0);
        if(r<=0) return;
        raw+=ch[0];
        if(raw.size()>=4&&raw[raw.size()-4]=='\r'&&raw[raw.size()-3]=='\n'&&
           raw[raw.size()-2]=='\r'&&raw[raw.size()-1]=='\n') break;
        if(raw.size()>65536) return;
    }

    std::istringstream hs(raw);
    std::string method,path,line;
    std::getline(hs,line);
    if(!line.empty()&&line.back()=='\r') line.pop_back();
    {std::istringstream ls(line);ls>>method>>path;}

    std::map<std::string,std::string> headers;
    long long content_length=0;
    while(std::getline(hs,line)){
        if(!line.empty()&&line.back()=='\r') line.pop_back();
        if(line.empty()) break;
        auto col=line.find(':');
        if(col!=std::string::npos){
            std::string k=to_lower(str_trim(line.substr(0,col)));
            std::string v=str_trim(line.substr(col+1));
            headers[k]=v;
            if(k=="content-length"){
                try{ content_length=std::stoll(v); }catch(...){}
            }
        }
    }

    if(method=="OPTIONS"){ send_text(sock,200,"OK",""); return; }
    if(method=="GET"&&path=="/ping"){ send_text(sock,200,"OK","MJJB_SERVER_OK"); return; }

    if(method=="POST"&&path=="/cipher"){
        std::string ct=headers.count("content-type")?headers["content-type"]:"";
        std::string boundary;
        auto bp=ct.find("boundary=");
        if(bp!=std::string::npos){
            boundary=str_trim(ct.substr(bp+9));
            if(!boundary.empty()&&boundary.front()=='"')
                boundary=boundary.substr(1,boundary.size()-2);
        }
        if(boundary.empty()){send_text(sock,400,"Bad Request","Missing boundary");return;}

        // Read body
        std::vector<uint8_t> body_vec;
        if(content_length>0){
            body_vec.resize((size_t)content_length);
            long long total=0;
            while(total<content_length){
                int want=(int)std::min((long long)65536,content_length-total);
                int r=recv(sock,(char*)body_vec.data()+total,want,0);
                if(r<=0) break;
                total+=r;
            }
        }

        auto fields=parse_multipart(body_vec.data(),(uint64_t)body_vec.size(),boundary);

        const uint8_t* file_ptr=nullptr; uint64_t file_size=0;
        std::string orig_filename="output";
        std::array<std::string,3> keys;
        std::string mode,stage_order;

        for(auto& f:fields){
            if     (f.name=="file")       {file_ptr=f.data_ptr;file_size=f.data_size;if(!f.filename.empty())orig_filename=f.filename;}
            else if(f.name=="key1")       keys[0]=std::string((char*)f.data_ptr,f.data_size);
            else if(f.name=="key2")       keys[1]=std::string((char*)f.data_ptr,f.data_size);
            else if(f.name=="key3")       keys[2]=std::string((char*)f.data_ptr,f.data_size);
            else if(f.name=="mode")       mode=std::string((char*)f.data_ptr,f.data_size);
            else if(f.name=="stage_order")stage_order=std::string((char*)f.data_ptr,f.data_size);
        }

        if(!file_ptr||file_size==0){send_text(sock,400,"Bad Request","No file");return;}
        if(keys[0].empty()||keys[1].empty()||keys[2].empty()){send_text(sock,400,"Bad Request","Keys required");return;}
        if(mode!="encode"&&mode!="decode") mode="encode";
        if(stage_order.empty()) stage_order="SHUFFLE,XOR,CHAIN";

        MappedBuf out_buf; uint64_t out_size=0;
        try{
            run_cipher(file_ptr,file_size,keys,stage_order,mode,out_buf,out_size);
        }catch(const std::exception& e){
            send_text(sock,500,"Internal Server Error",e.what()); return;
        }

        std::string dl_name;
        if(mode=="encode"){
            dl_name=orig_filename+".mjjb";
        }else{
            dl_name=orig_filename;
            std::string lower=dl_name;
            std::transform(lower.begin(),lower.end(),lower.begin(),::tolower);
            if(lower.size()>=5&&lower.substr(lower.size()-5)==".mjjb")
                dl_name=dl_name.substr(0,dl_name.size()-5);
        }

        std::string hdr_resp=
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
            "Content-Length: "+std::to_string(out_size)+"\r\n"
            "Content-Disposition: attachment; filename=\""+dl_name+"\"\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type\r\n"
            "Connection: close\r\n\r\n";
        send_all(sock,hdr_resp.c_str(),hdr_resp.size());

        size_t sent=0;
        while(sent<out_size){
            size_t chunk=std::min((size_t)CHUNK_SIZE,out_size-sent);
            ssize_t r=send(sock,(char*)out_buf.ptr+sent,(int)chunk,0);
            if(r<=0) break;
            sent+=(size_t)r;
        }
        return;
    }

    send_text(sock,404,"Not Found","Not Found");
}

// ─── Server thread entry ─────────────────────────────────────────────────────
static void* server_thread(void* arg){
    int port=*(int*)arg; free(arg);
    g_stop=0;

    int srv=socket(AF_INET,SOCK_STREAM,0);
    if(srv<0){LOGE("socket() failed");return nullptr;}
    g_srv=srv;

    int yes=1;
    setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family=AF_INET;
    addr.sin_port=htons((uint16_t)port);
    addr.sin_addr.s_addr=INADDR_ANY;

    if(bind(srv,(sockaddr*)&addr,sizeof(addr))<0){LOGE("bind() failed");close(srv);return nullptr;}
    if(listen(srv,8)<0){LOGE("listen() failed");close(srv);return nullptr;}

    LOGI("MJJB server listening on port %d",port);

    while(!g_stop){
        sockaddr_in client_addr{};
        socklen_t addr_len=sizeof(client_addr);
        int client=accept(srv,(sockaddr*)&client_addr,&addr_len);
        if(client<0){if(!g_stop)LOGE("accept() failed");break;}

        struct timeval tv{600,0};
        setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
        setsockopt(client,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));

        handle_client(client);
        close(client);
    }
    close(srv); g_srv=-1;
    return nullptr;
}

// ═══════════════════════════════════════════════════════════════════════════
//  JNI ENTRY POINTS
// ═══════════════════════════════════════════════════════════════════════════

extern "C" {

JNIEXPORT void JNICALL
Java_com_mjjbencodedecode_1system_MainActivity_nativeStartServer(JNIEnv*, jobject, jint port){
    int* p=(int*)malloc(sizeof(int)); *p=(int)port;
    pthread_t t; pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
    pthread_create(&t,&attr,server_thread,p);
    pthread_attr_destroy(&attr);
}

JNIEXPORT void JNICALL
Java_com_mjjbencodedecode_1system_MainActivity_nativeStopServer(JNIEnv*, jobject){
    g_stop=1;
    if(g_srv>=0){ shutdown(g_srv,SHUT_RDWR); close(g_srv); g_srv=-1; }
}





} // extern "C"