#include<iostream>
#include<NTL/ZZ.h>
#include<NTL/vector.h>
using namespace NTL;

typedef struct point{
    ZZ x;
    ZZ y;
}Point;

// NIST parameters for 192 bit
ZZ p = conv<ZZ>("57896044618658097711785492504343953926634992332820282019728792003956564819949");   //feild parameter
//ZZ p = power(ZZ(2), long(192)) - power(ZZ(2), long(64)) - 1;    //feild parameter
ZZ a = ZZ(486662);  // elliptic cuve parameter
//ZZ a = ZZ(-3);  // elliptic cuve parameter
ZZ b = conv<ZZ>("2455155546008943817740293915197451784769108058161191238065"); // elliptic curve parameter
ZZ n = conv<ZZ>("7237005577332262213973186563042994240857116359379907606001950938285454250989"); // order of elliptic curve
//ZZ n = conv<ZZ>("6277101735386680763835789423176059013767194773182842284081"); // order of elliptic curve

ZZ Px = conv<ZZ>("2"); // x cordinate of base point
ZZ Py = conv<ZZ>("3"); // y cordinate of base point

//ZZ Px = conv<ZZ>("602046282375688656758213480587526111916698976636884684818"); // x cordinate of base point
//ZZ Py = conv<ZZ>("174050332293622031404857552280219410364023488927386650641"); // y cordinate of base point

Point point_doubling(Point P){
    ZZ x1 = P.x, y1 = P.y;
    if(y1 == 0){
        std::cout<<"Point doubling error";
        return {ZZ(0), ZZ(0)};
    }
    ZZ m = ((3*x1*x1 + a) * InvMod((2*y1) % p, p)) % p;
    ZZ x3 = (m*m - 2*x1) % p;
    ZZ y3 = (m*(x1 - x3) - y1) % p;
    std::cout<<"\nP3: x = "<<x3<<"\ny = "<<y3<<"\n";
    return {x3, y3};
}

Point point_addition(Point P, Point Q){
    ZZ x1 = P.x, y1 = P.y, x2 = Q.x, y2 = Q.y;
    if(y1 == y2 or y1 == -y2){
        std::cout<<"\nPoint Addition invalid operation";
        return {ZZ(0), ZZ(0)};
    }
    ZZ m = (((y2 - y1) % p) * InvMod((x2 - x1) % p, p)) % p;
    ZZ x3 = ((m*m) % p - (x1 + x2) % p) % p;
    ZZ y3 = ((m*(x1 - x3)) % p - y1) % p;
    std::cout<<"\nP3: x = "<<x3<<"\ny = "<<y3<<"\n";
    return {x3, y3};
}

Point scalar_multiply(ZZ k, Point P){
    k = ZZ(11); //1011 binario
    std::cout<<"\n k = "<<k<<"\n P.x = "<<P.x<<"\n P.y = "<<P.y<<"\n";
    Point P1 = P, P2;
    bool p2_initialized = false;
    while(k != ZZ(0)){
        if(operator&(k, ZZ(1)) > ZZ(0)){
            if(!p2_initialized){
                p2_initialized = true;
                P2 = P1;
            }
            else{
                std::cout <<"\nADD\n";
                P2 = point_addition(P1, P2);
                
                std::cout << "P2 : x = " << P2.x << " , y = " << P2.y << "\n";
            }
        }
        std::cout <<"\nDOUBLE\n";
        P1 = point_doubling(P1);
        
        std::cout << "P1 : x = " << P1.x << " , y = " << P1.y << "\n";
        k = RightShift(k, long(1));
    }
    return P2;
}


ZZ ecc_y_val(ZZ x){
    //return (power(x, long(3)) + a*x + b) % p;
    return (power(x, long(3)) + a*power(x, long(2)) + x) % p;
}

Point encode_message_to_point(ZZ message){
    ZZ xj = 100*message;
    for(long j = 0; j<100; j++){
        ZZ sj = ecc_y_val(xj + j);
        std::cout<<"\nsj"<<sj;
        if(PowerMod(sj, (p-1)/2, p) == ZZ(1)){
            ZZ exp = (p-1)/2;
            std::cout<<"\nexp"<<exp;
            ZZ yj = SqrRootMod(sj, p);
            return {xj + j, yj};
        }
    }
    std::cout<<"\nMessage encoding failed";
    return {ZZ(0), ZZ(0)};
}

ZZ choose_random_integer(ZZ num){
    ZZ private_key = RandomBnd(num);
    while(private_key == ZZ(0))
        private_key = RandomBnd(num);
    return private_key;
}

Point generate_public_key(ZZ private_key){
    return scalar_multiply(private_key, {Px, Py});
}

Vec<Point> encrypt_message(Point message, Point public_key){
    ZZ k = choose_random_integer(n);
    Point C1 = scalar_multiply(k, {Px, Py});
    Point k_mul_public_key = scalar_multiply(k, public_key);
    Point C2 = point_addition(message, k_mul_public_key);
    Vec<Point> cipher;
    cipher.append(C1);
    cipher.append(C2);
    return cipher;
}

ZZ decrypt_message(Vec<Point> cipher, ZZ private_key){
    Point c1 = cipher[0];
    Point c2 = cipher[1];
    Point private_key_mul_c1 = scalar_multiply(private_key, c1);
  
    Point M = point_addition(c2, {private_key_mul_c1.x, -private_key_mul_c1.y});
    return M.x/100;
}

int main(){
    ZZ message;
    std::cout<<"\nEnter message to encrypt using ECC : ";
    std::cin>>message;
    
    //Generating private and public keys
    ZZ private_key = choose_random_integer(n);
    std::cout<<"\nprivate key : "<<private_key<<"\n";

    Point public_key = generate_public_key(private_key);
    std::cout<<"\npublic key : "<<"x = "<<public_key.x<<" , "<<"y = "<<public_key.y<<"\n";

    Point M = encode_message_to_point(message);
    std::cout<<"\nencoded message point : x = "<<M.x<<" , y = "<<M.y<<"\n";

    Vec<Point> cipher = encrypt_message(M, public_key);
    std::cout<<"\nc1 : x = "<<cipher[0].x<<", y = "<<cipher[0].y<<"\n";
    std::cout<<"\nc2 : x = "<<cipher[1].x<<", y = "<<cipher[1].y<<"\n";

    ZZ decrypted_message = decrypt_message(cipher, private_key);
    std::cout<<"\ndecrypted message = "<<decrypted_message<<"\n";
    
    return 0;
}