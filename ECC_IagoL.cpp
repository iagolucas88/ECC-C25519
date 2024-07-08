//Code developed by Iago Lucas (iagolbg@gmail.com) 
//for his master's degree in Mechatronic Engineering at the 
//Federal University of Rio Grande do Norte (Brazil).

//Elliptic Curve Cryptography (ECC) for IoT devices 
//(microcontrollers) implementing Curve25519 developed by Daniel J. Bernstein.

#include <iostream>
#include <gmp.h>

using namespace std;


typedef struct point{
    mpz_t x;
    mpz_t y;
} Point;

//Parametros NIST para curva com 192 bit (tem q ser para c25519)
ZZ p = power(ZZ(2), long(192)) - power(ZZ(2), long(64)) - 1;    //feild parameter
ZZ a = ZZ(-3);  // elliptic cuve parameter
ZZ b = conv<ZZ>("2455155546008943817740293915197451784769108058161191238065"); // elliptic curve parameter
ZZ n = conv<ZZ>("6277101735386680763835789423176059013767194773182842284081"); // order of elliptic curve
ZZ Px = conv<ZZ>("602046282375688656758213480587526111916698976636884684818"); // x cordinate of base point
ZZ Py = conv<ZZ>("174050332293622031404857552280219410364023488927386650641"); // y cordinate of base point


//1. Curva eliptica 'Curve25519'
ZZ ecc_25519(ZZ x){
    return (power(x, long(3)) + a*power(x, long(2)) + x)/b % p;
    //return (power(x, long(3)) + a*x + b) % p;
}

//2. Codifica a mensagem para o ponto
Point encode_message_to_point(ZZ message){
    ZZ xj = 100*message;
    for(long j = 0; j<100; j++){
        ZZ sj = ecc_25519(xj + j);
        if(PowerMod(sj, (p-1)/2, p) == ZZ(1)){
            ZZ yj = SqrRootMod(sj, p);
            return {xj + j, yj};
        }
    }
    std::cout<<"\nMessage encoding failed";
    return {ZZ(0), ZZ(0)};
}


//3. Calcula o 'DOUBLE' retornado P3(X3,Y3) somente se Y1 != 0
Point point_doubling(Point P){
    ZZ x1 = P.x, y1 = P.y;
    if(y1 == 0){
        std::cout<<"Point doubling error";
        return {ZZ(0), ZZ(0)};
    }
    ZZ m = ((3*x1*x1 + a) * InvMod((2*y1) % p, p)) % p;
    ZZ x3 = (m*m - 2*x1) % p;
    ZZ y3 = (m*(x1 - x3) - y1) % p;
    return {x3, y3};
}

//4. Calcula o 'ADD' retornado P3(X3,Y3) somente se Y1 != +/- Y2
Point point_addition(Point P, Point Q){
    ZZ x1 = P.x, y1 = P.y, x2 = Q.x, y2 = Q.y;
    if(y1 == y2 or y1 == -y2){
        std::cout<<"\nPoint Addition invalid operation";
        return {ZZ(0), ZZ(0)};
    }
    ZZ m = (((y2 - y1) % p) * InvMod((x2 - x1) % p, p)) % p;
    ZZ x3 = ((m*m) % p - (x1 + x2) % p) % p;
    ZZ y3 = ((m*(x1 - x3)) % p - y1) % p;
    return {x3, y3};
}

//5. Multiplicacao escalar chama 'ADD' com a condição de k existir (k shift até encerrar os bits)
//P1 sempre sera calculado pelo 'DOUBLE'

Point scalar_multiply(ZZ k, Point P){
    // std::cout<<"\n k = "<<k<<"\n P.x = "<<P.x<<"\n P.y = "<<P.y<<"\n";
    Point P1 = P, P2;
    bool p2_initialized = false;
    while(k != ZZ(0)){
        if(operator&(k, ZZ(1)) > ZZ(0)){
            if(!p2_initialized){
                p2_initialized = true;
                P2 = P1;
            }
            else{
                P2 = point_addition(P1, P2);
            }
        }
        P1 = point_doubling(P1);
        k = RightShift(k, long(1));
    }
    return P2;
}


//6.Gerar um numero inteiro randomico e retorna a CHAVE PRIVADA
ZZ generate_rand_int(ZZ num){
    ZZ private_key = RandomBnd(num);
    while(private_key == ZZ(0))
        private_key = RandomBnd(num);
    return private_key;
}

//7. Gera a CHAVE PUBLICA ultilizando a multiplicacao escalar da CHAVE PRIVADA com o Ponto base dado (Px,Py)
//Retorna P2(X2, Y2)
Point generate_public_key(ZZ private_key){
    return scalar_multiply(private_key, {Px, Py});
}

//8. Encripta a mensagem ultilizando a CHAVE PUBLICA
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

//9. Decripta a mensagem ultilizando a CHAVE PRIVADA
ZZ decrypt_message(Vec<Point> cipher, ZZ private_key){
    Point c1 = cipher[0];
    Point c2 = cipher[1];
    Point private_key_mul_c1 = scalar_multiply(private_key, c1);
    Point M = point_addition(c2, {private_key_mul_c1.x, -private_key_mul_c1.y});
    return M.x/100;
}

int main()
{
    mpz_t x;
    mpz_init(x);
    mpz_set_ui(x,277887);

    //não posso usar a pois é GMP, tem q ser gmp_printf
    //cout << "Valor de a =" << a << endl;
    
    cout << endl;

    mpz_t b;
    mpz_init(b);
    //adere o texto 888777... em b na base 10
    float success = mpz_set_str(b,"88877777777777878",10);

    cout << "valor sucess = " << success << endl; // if success = -1 base was invalid 0 if success 
    cout<< "Valor B = ";
    gmp_printf ("% Zd ", b);

    cout << endl;

    cout << "Valor X = ";
    gmp_printf ("% Zd ", x);


    //limpar variáveis para liberar memória
    mpz_clear(x);
    mpz_clear(b);

    cout << endl << endl;

    return 0;
}



/*CODIGO ANTERIOR ****************************************
//Boost with GMP
#include <boost/multiprecision/gmp.hpp>
//#include <gmp.h>
#include <iostream>


//teste conversao e registro
// #include <string>,
// #include <fstream>
// #include <sstream>

//tempo
#include <bits/stdc++.h>

using namespace boost::multiprecision;
//typedef number<mpz_int> big_int;

int main() {
    //Ao iniciar um valor boost com GMP de backend, necessita declarar e iniciar.
    mpz_t base, exponent, result;
    mpz_init(base);
    mpz_init(exponent);
    mpz_init(result);



    //Necessita definir um valor 
    //Necessita definir base?
    //mpz_set_str(base, "2", 10);  // Define a base como 2
    //mpz_set_str(exponent, "1000", 10);  // Define o expoente como 1000

    //mpz_pow_ui(result, base, mpz_get_ui(exponent)); // Calcula base elevado ao expoente

    //std::cout << "2^1000 = " << mpz_get_str(nullptr, 10, result) << std::endl;


    //Sempre deve-se encerrar os valores para liberar memória
    mpz_clear(base);
    mpz_clear(exponent);
    mpz_clear(result);

    return 0;
}
FIM DO CODICO ANTERIOR*/