#include<stdio.h>
#include<string.h>

typedef struct{  
    unsigned int count[2];  
    unsigned int state[4];  
    unsigned char buffer[64];  
}MD5_data;

unsigned char padding[64]={0x80};

/*压缩函数的实现*/ 
unsigned int F(unsigned int b,unsigned int c,unsigned int d){
	return (b&c)|((~b)&d);
}
unsigned int G(unsigned int b,unsigned int c,unsigned int d){
	return (b&d)|(c&(~d));
}
unsigned int H(unsigned int b,unsigned int c,unsigned int d){
	return b^c^d;
}
unsigned int I(unsigned int b,unsigned int c,unsigned int d){
	return c^(b|(~d)); 
}

/*左移*/ 
unsigned int Rotate_Left(unsigned int num,unsigned int bit){
	return (num<<bit)|(num>>(32-bit));
}

/*轮转函数的实现*/
void FF(unsigned int &a,unsigned int b,unsigned int c,unsigned int d,unsigned int Xk,unsigned int s,unsigned int Ti){
	unsigned int temp=a+F(b,c,d)+Xk+Ti;
	a=b+Rotate_Left(temp,s);
}
void GG(unsigned int &a,unsigned int b,unsigned int c,unsigned int d,unsigned int Xk,unsigned int s,unsigned int Ti){
	unsigned int temp=a+G(b,c,d)+Xk+Ti;
	a=b+Rotate_Left(temp,s);
}
void HH(unsigned int &a,unsigned int b,unsigned int c,unsigned int d,unsigned int Xk,unsigned int s,unsigned int Ti){
	unsigned int temp=a+H(b,c,d)+Xk+Ti;
	a=b+Rotate_Left(temp,s);
}
void II(unsigned int &a,unsigned int b,unsigned int c,unsigned int d,unsigned int Xk,unsigned int s,unsigned int Ti){
	unsigned int temp=a+I(b,c,d)+Xk+Ti;
	a=b+Rotate_Left(temp,s);
}

void Initialize(MD5_data *content);
void Update(MD5_data *content,unsigned char *input,unsigned int inputlen); 
void Transform(unsigned int state[4],unsigned char block[64]);
void Final(MD5_data *content,unsigned char digest[16]);
void Encode(unsigned char *output,unsigned int *input,unsigned int len);  
void Decode(unsigned int *output,unsigned char *input,unsigned int len);   


/*初始化的实现*/
void Initialize(MD5_data *content){
	content->count[0]=0;
	content->count[1]=0;
	content->state[0]=0x67452301;
	content->state[1]=0xefcdab89;
	content->state[2]=0x98badcfe;
	content->state[3]=0x10325476;
} 


void Update(MD5_data *content,unsigned char *input,unsigned int inputlen){  
    unsigned int i=0,index=0,partlen=0;  
    index=(content->count[0]>>3)&0x3F;  
    partlen=64-index;  
    content->count[0]+=inputlen<<3;  
    if(content->count[0]<(inputlen<<3))  
        content->count[1]++;  
    content->count[1]+=inputlen>>29;  
  
    if(inputlen>=partlen){  
        memcpy(&content->buffer[index],input,partlen);  
        Transform(content->state,content->buffer);  
        for(i=partlen;i+64<=inputlen;i+=64)  
            Transform(content->state,&input[i]);  
        index=0;  
    }  
    else{  
        i=0;  
    }  
    memcpy(&content->buffer[index],&input[i],inputlen-i);  
}  


/*把Unsigned int转化为unsigned char*/ 
void Encode(unsigned char *output,unsigned int *input,unsigned int len){  
    for(int i=0,j=0;j<len;i++){
        output[j] = static_cast<unsigned char>(input[i] & 0xff);  
        output[j + 1] = static_cast<unsigned char>((input[i] >> 8) & 0xff);  
        output[j + 2] = static_cast<unsigned char>((input[i] >> 16) & 0xff);  
        output[j + 3] = static_cast<unsigned char>((input[i] >> 24) & 0xff); 
        j+=4;  
    }  
}  
/*把Unsigned char转化为unsigned int*/ 
void Decode(unsigned int *output,unsigned char *input,unsigned int len){  
    for(int i=0,j=0;j<len;i++){  
        output[i] = ((static_cast<unsigned int>(input[j]))  
            |((static_cast<unsigned int>(input[j + 1])) << 8)  
            |((static_cast<unsigned int>(input[j + 2])) << 16)  
            |((static_cast<unsigned int>(input[j + 3])) << 24));  
        j+=4;  
    }  
}


void Transform(unsigned int state[4],unsigned char block[64]){  
    unsigned int a=state[0];  
    unsigned int b=state[1];  
    unsigned int c=state[2];  
    unsigned int d=state[3];  
    unsigned int x[64];  
  
    Decode(x, block, 64);  
    FF(a, b, c, d, x[0], 7, 0xd76aa478);  
    FF(d, a, b, c, x[1], 12, 0xe8c7b756);  
    FF(c, d, a, b, x[2], 17, 0x242070db);  
    FF(b, c, d, a, x[3], 22, 0xc1bdceee);  
    FF(a, b, c, d, x[4], 7, 0xf57c0faf);  
    FF(d, a, b, c, x[5], 12, 0x4787c62a);  
    FF(c, d, a, b, x[6], 17, 0xa8304613);  
    FF(b, c, d, a, x[7], 22, 0xfd469501);  
    FF(a, b, c, d, x[8], 7, 0x698098d8);  
    FF(d, a, b, c, x[9], 12, 0x8b44f7af);  
    FF(c, d, a, b, x[10], 17, 0xffff5bb1);  
    FF(b, c, d, a, x[11], 22, 0x895cd7be);  
    FF(a, b, c, d, x[12], 7, 0x6b901122);  
    FF(d, a, b, c, x[13], 12, 0xfd987193);  
    FF(c, d, a, b, x[14], 17, 0xa679438e);  
    FF(b, c, d, a, x[15], 22, 0x49b40821);  
  
  
    GG(a, b, c, d, x[1], 5, 0xf61e2562);  
    GG(d, a, b, c, x[6], 9, 0xc040b340);  
    GG(c, d, a, b, x[11], 14, 0x265e5a51);  
    GG(b, c, d, a, x[0], 20, 0xe9b6c7aa);  
    GG(a, b, c, d, x[5], 5, 0xd62f105d);  
    GG(d, a, b, c, x[10], 9, 0x2441453);  
    GG(c, d, a, b, x[15], 14, 0xd8a1e681);  
    GG(b, c, d, a, x[4], 20, 0xe7d3fbc8);  
    GG(a, b, c, d, x[9], 5, 0x21e1cde6);  
    GG(d, a, b, c, x[14], 9, 0xc33707d6);  
    GG(c, d, a, b, x[3], 14, 0xf4d50d87);  
    GG(b, c, d, a, x[8], 20, 0x455a14ed);  
    GG(a, b, c, d, x[13], 5, 0xa9e3e905);  
    GG(d, a, b, c, x[2], 9, 0xfcefa3f8);  
    GG(c, d, a, b, x[7], 14, 0x676f02d9);  
    GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);  
  
  
    HH(a, b, c, d, x[5], 4, 0xfffa3942);  
    HH(d, a, b, c, x[8], 11, 0x8771f681);  
    HH(c, d, a, b, x[11], 16, 0x6d9d6122);  
    HH(b, c, d, a, x[14], 23, 0xfde5380c);  
    HH(a, b, c, d, x[1], 4, 0xa4beea44);  
    HH(d, a, b, c, x[4], 11, 0x4bdecfa9);  
    HH(c, d, a, b, x[7], 16, 0xf6bb4b60);  
    HH(b, c, d, a, x[10], 23, 0xbebfbc70);  
    HH(a, b, c, d, x[13], 4, 0x289b7ec6);  
    HH(d, a, b, c, x[0], 11, 0xeaa127fa);  
    HH(c, d, a, b, x[3], 16, 0xd4ef3085);  
    HH(b, c, d, a, x[6], 23, 0x4881d05);  
    HH(a, b, c, d, x[9], 4, 0xd9d4d039);  
    HH(d, a, b, c, x[12], 11, 0xe6db99e5);  
    HH(c, d, a, b, x[15], 16, 0x1fa27cf8);  
    HH(b, c, d, a, x[2], 23, 0xc4ac5665);  
  
  
    II(a, b, c, d, x[0], 6, 0xf4292244);  
    II(d, a, b, c, x[7], 10, 0x432aff97);  
    II(c, d, a, b, x[14], 15, 0xab9423a7);  
    II(b, c, d, a, x[5], 21, 0xfc93a039);  
    II(a, b, c, d, x[12], 6, 0x655b59c3);  
    II(d, a, b, c, x[3], 10, 0x8f0ccc92);  
    II(c, d, a, b, x[10], 15, 0xffeff47d);  
    II(b, c, d, a, x[1], 21, 0x85845dd1);  
    II(a, b, c, d, x[8], 6, 0x6fa87e4f);  
    II(d, a, b, c, x[15], 10, 0xfe2ce6e0);  
    II(c, d, a, b, x[6], 15, 0xa3014314);  
    II(b, c, d, a, x[13], 21, 0x4e0811a1);  
    II(a, b, c, d, x[4], 6, 0xf7537e82);  
    II(d, a, b, c, x[11], 10, 0xbd3af235);  
    II(c, d, a, b, x[2], 15, 0x2ad7d2bb);  
    II(b, c, d, a, x[9], 21, 0xeb86d391);  
    state[0]+=a;  
    state[1]+=b;  
    state[2]+=c;  
    state[3]+=d;  
}

void Final(MD5_data *content,unsigned char digest[16]){  
    unsigned int index=0,padlen=0;  
    unsigned int tempState[4],tempCount[2];
    unsigned char bits[8];  
    memcpy(tempState, content->state, 16);  
    memcpy(tempCount, content->count, 8);
    
    Encode(bits,content->count,8); 
    index=static_cast<unsigned int>((content->count[0]>>3)&0x3F);  
    padlen=(index<56)?(56-index):(120-index);   
    Update(content,padding,padlen);  
    Update(content,bits,8);  
	Encode(digest,content->state,16);  
	
	memcpy(content->state, tempState, 16);  
    memcpy(content->count, tempCount, 8);
}  

int main(){
	int i;
	unsigned char input[]="abcdefg";
	unsigned char output[16];
	
	MD5_data md5;
	Initialize(&md5);
	Update(&md5,input,strlen((char *)input));
	Final(&md5,output);
	
    printf("md5(%s,32):",input);
    for(i=0;i<16;i++){
    	printf("%02x",output[i]);
	}
	printf("\nmd5(%s,16):",input);
	for(i=4;i<12;i++){  
        printf("%02x",output[i]);    
    }
    
	return 0; 
}
