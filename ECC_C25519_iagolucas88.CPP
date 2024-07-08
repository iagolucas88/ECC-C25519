/*____________________________________________________________________________
Code developed by Iago Lucas (iagolbg@gmail.com | GitHub: iagolucas88) 
for his master's degree in Mechatronic Engineering at the 
Federal University of Rio Grande do Norte (Brazil).

Elliptic Curve Cryptography (ECC) for IoT devices 
(microcontrollers) implementing Curve25519 developed by Daniel J. Bernstein.
____________________________________________________________________________*/

#include <iostream>
#include <gmp.h>
#include <fstream> //Para gerar seed pelo /dev/urandom

using namespace std;

//Cria uma estrutura de ponto (x, y) inteiro
struct Ponto{
    mpz_t x, y;

    //Construtor para inicializar o ponto com inteiro mpz_t
    Ponto(const mpz_t x_intz, const mpz_t y_intz){
        mpz_init_set(x, x_intz);
        mpz_init_set(y, y_intz);
    }

    //Destrutor para liberar a memória
    ~Ponto(){
        mpz_clear(x);
        mpz_clear(y);
    }
};

//*******DECLARA GLOBALMENTE PARAMETROS CURVA ELIPTICA [E: y² = x² + a*x + b (mod p)]*********************
//E: curva eliptica no campo GF(q) onde |E| = h*n
//p: numero primo do campo | n: ordem da curva (numero primo enorme)| h: co-fator (numero pequeno)
//a, b: Curva de Weierstrass (Wa,b) onde 'a' e 'b' são elementos de GF(q) com 4a³ + 27b² != 0 
//P1: ponto base (x1, y1) da curva (qualquer ponto da curva pode ser gerado pelo grupo ciclico <P> ={kP | k = 0,1,2,...} de E)
mpz_t p, n, a, x1, y_1;  
//mpz_t h, b; //'h' e 'b' nao serao ultilizados, economizando memoria

//1. Curva eliptica 'Curve25519' (E). Mod q
//Codifica a mensagem para os pontos na curva ultilizada.
Ponto codifica_mensagem_para_ponto_da_c25519(mpz_t msg){

    mpz_t x_msg, y_msg, c25519_msg, A, B, C, exp_euler, teste_euler;
    mpz_inits(x_msg, y_msg, c25519_msg, A, B, C, exp_euler, teste_euler, NULL);

    //Necessario copiar para nao alterar o valor da mensagem original e evitar conflitos
    mpz_set(x_msg, msg); 
    
    cout << "\n**************INICIO FUNCAO 1******************\n" << endl;


    //Armazena a quantidade de digitos da mensagem na base 10
    int tamanho_msg = mpz_sizeinbase(msg, 10);
    int dif_digitos = 0;
    cout << "\nQuantidade de digitos da mensagem: " << tamanho_msg << endl;

    dif_digitos = 99 - tamanho_msg; //Diferenca de digitos para inserir zeros no 'x_msg'

    if(dif_digitos > 0){
        //Multiplica a mensagem até 99 vezes a quantidade de digitos para garantir que sejam maior que p (aprox 76 digitos)
        for(int i = 0; i < dif_digitos; i++){        
            mpz_mul_ui(x_msg, x_msg, 10); 
        }
    }

    //Mensagem estendida para efetuar os calculos
    gmp_printf("\nx_msg: %Zd", x_msg);

    //Teste de Euler [y^((p-1)/2) = 1 (mod p)]: verifica se 'y' eh residuo quadratico no campo Fp para um primo ímpar 'p'
    //Para C25519 p = 2^(255) - 19, logo (p - 1) = 2^(255) - 20, assim 20 é divisível por 4.
    //Portanto simplificando o teste, temos: y^[(p+1)/4] = 1 (mod p)
    mpz_add_ui(exp_euler, p, 1); //Expoente do Teste de Euler: exp_euler = (p+1)/4
    mpz_cdiv_q_ui(exp_euler, exp_euler, 4); //gmp_printf("\nexp euler: %Zd", exp_euler);

    //Testa se P é primo (quanto maior as repeticoes um nao-primo pode ser definido como provavel)
    int primo = mpz_probab_prime_p(p, 50); //Numero de repeticoes para determinar se eh primo
    cout << "\n\n2=primo | 1=provavel | 0=nao-primo: " << primo << endl;

    tamanho_msg = 2; //Numero de vezes necessario para determinar um inteiro y² que passe no Teste de Euler
    for(int j = 0; j < tamanho_msg; j++){
        //y² = x³ + a*x² + x
        //c25519_msg + j = retorna um número y² na c25519 viável?
        mpz_add_ui(x_msg, x_msg, j);  //ULTILIZAR A FUNCAO MPZ_NEXTPRIME NO LUGAR????

        //A = x²
        mpz_mul(A, x_msg, x_msg);
        gmp_printf("\nx²: %Zd", A);

        //B = x³
        mpz_mul(B, A, x_msg);
        gmp_printf("\nx³: %Zd", B);

        //C = a * x² (onde, a = 486662)
        mpz_mul(C, a, A);
        gmp_printf("\nx²*a: %Zd", C);

        //y² = x_msg³ + a*x_msg² + x_msg (mod p)
        mpz_add(c25519_msg, B, C); 
        mpz_add(c25519_msg, c25519_msg, x_msg);
        gmp_printf("\n\ny² Sem MOD: %Zd", c25519_msg);
        mpz_mod(c25519_msg, c25519_msg, p); //se resultar no mesmo número o resto eh o msm valor?
        gmp_printf("\ny² Com MOD: %Zd", c25519_msg); //o numerador não pode ser menos, como 'p' eh enorme, o resultado eh o mesmo valor 

        //Calcula Teste de Euler = y^[(p+1)/4] (mod p)
        mpz_powm_sec(teste_euler, c25519_msg, exp_euler, p); // mpz_powm_SEC eh ultilizado em criptografia pela segurança, pode levar mais tempo
        gmp_printf("\n\nTeste Euler: %Zd", teste_euler);
        //mpz_sqrt(teste_euler, teste_euler);
        //gmp_printf("\n\nTeste Euler raiz: %Zd", teste_euler);

        //Se o resto do 'teste_euler' e de 'um' forem o mesmo ao dividir 'p'
        cout << "\n\n**********TESTE RESTOS**********" << endl;

        mpz_t um, resto1, resto2;
        mpz_init_set_ui(um, 1);
        mpz_init_set_ui(resto1, 0);
        mpz_init_set_ui(resto2, 0);

        //Divide retornando o resto
        mpz_cdiv_r(resto1, teste_euler, p);
        gmp_printf("\nResto Euler: %Zd", resto1);

        mpz_cdiv_r(resto2, um, p);
        gmp_printf("\n\nResto Um:    %Zd", resto2);

        cout << "\n\n**************************" << endl;

        //Retorna != 0 se teste_euler for congruente a 'um' mod 'p'
        //int congruente = mpz_congruent_p(teste_euler, um, p);
        int congruente = mpz_congruent_p(teste_euler, um, p);
        cout << "\nCongruente se != 0: " << congruente << endl;

        //Compara e se retornar 0 eh pq sao iguais
        if(mpz_cmp(resto1, resto2) == 0){
            cout << "\nEH CONGRUENTE!!!" << j << "\n, ";

            return {x_msg, x_msg + j};
            //return P_msg;
        }
    }
    
    cerr << "\nCodificacao da mensagem falhou!" << endl;
    mpz_set_ui(x_msg, 0);
    mpz_set_ui(y_msg, 0);

    cout << "\n**************FIM FUNCAO 1******************\n" << endl;

    //Libera memoria alocada
    mpz_clears(x_msg, y_msg, c25519_msg, A, B, C, NULL);

    return {x_msg, y_msg};
}

/*NAO TESTADO
//2. Montgomery Ladder
FAZ-SE NECESSÁRIO OU PODE CALCULAR PELAS FÓMULAS DA ECC25519?????
*/
/*
//3. Calcula o 'ADD' retornado P3(X3,Y3) somente se Y1 != +/- Y2
//P + Q = Pm + Pn = Pm+n(Xm+n : Zm+n)
Ponto add_ponto(Ponto P, Ponto Q){
    //A coordenada Zm != +/- Zn
    //int cmp = mpz_cmpabs_ui(P.y, Q.y);
    if(mpz_cmpabs_ui(P.y, Q.y) == 0){
        cerr << "Erro Ponto-ADD (Zm = +/- Zn)!" << endl;
        mpz_set_ui(P.x, 0);
        mpz_set_ui(P.y, 0);
        return {P.x, P.y}; //REVER!!!!!!!!!!!!!!!!!!!!!!!
    }

    Ponto Pm, Pn;
    mpz_t A, B, C, D, E, F, G, H;
    mpz_inits(A, B, C, D, E, F, G, H, NULL);

 
    //Xm+n = Zm-n*[(Xm - Zm)*(Xn + Zn) + (Xm + Zm)*(Xn - Zn)]²
    //Zm+n = Xm-n*[(Xm - Zm)*(Xn + Zn) - (Xm + Zm)*(Xn - Zn)]²

    //A = Xm - Zm
    mpz_sub(A, P.x, P.y);

    //B = Xn + Zn
    mpz_add(B, Q.x, Q.y);

    //C = Xm + Zm
    mpz_add(C, P.x, P.y);

    //D = Xn - Zn
    mpz_sub(D, Q.x, Q.y);

    //E = A*B -> (Xm - Zm)*(Xn + Zn)
    mpz_mul(E, A, B);

    //F = C*D -> (Xm + Zm)*(Xn - Zn)
    mpz_mul(F, C, D);

    //G = E+F -> (Xm - Zm)*(Xn + Zn) + (Xm + Zm)*(Xn - Zn)
    mpz_add(G, E, F);

    //H = E-F -> (Xm - Zm)*(Xn + Zn) - (Xm + Zm)*(Xn - Zn)
    mpz_sub(H, E, F);

    //I = G² -> [(Xm - Zm)*(Xn + Zn) + (Xm + Zm)*(Xn - Zn)]²
    mpz_mul(I, G, G);

    //J = H² -> [(Xm - Zm)*(Xn + Zn) - (Xm + Zm)*(Xn - Zn)]²
    mpz_mul(J, H, H);

    //Libera memoria alocada
    mpz_clears(A, B, C, D, E, F, G, H, NULL);

    return ({P.x, P.y}, {Q.x, Q.y});
}
*/
//4. Calcula o 'DOUBLE' retornado P3(X3,Y3) somente se Y1 != 0 
//Quando m = n, 2*Pn = P_(2n)(X_(2n) : Z_(2n))
Ponto double_ponto(Ponto P){
    //A coordenada Z !=0
    //int cmp = mpz_cmp_ui(P.y, 0);
    if(mpz_cmp_ui(P.y, 0) == 0){
        cerr <<"Erro Ponto-Double (Y = 0)!" << endl;
        mpz_set_ui(P.x, 0);
        mpz_set_ui(P.y, 0);
        return {P.x, P.y};
    }
/*_________________________________________________________________________________________________
    FORMULAS RETIRADAS DO TOPICO "3.2 Definition of a Twisted Montgomery Curve over a Tower Field"
    An Implementation of ECC with Twisted Montgomery Curve over 32nd Degree Tower Field on Arduino Uno
    ___________________________________________________________________________________________________*/

    //as formulas estão ligeira mente diferentes do que foi apresentado no artigo, tópico real 2.4
    //Ponto Pn;
    mpz_t A, B, C, D, E, F, G, H, Pn_x, Pn_y;
    mpz_inits(A, B, C, D, E, F, G, H, Pn_x, Pn_y, NULL);

 
    //X2n = (Xn + Zn)² * (Xn - Zn)²
    //4*XnZn = (Xn + Zn)² - (Xn - Zn)²
    //Z2n = (4*XnZn)*((Xn - Zn)² + ((a + 2)/4)*(4*XnZn))

    //A = (a + 2)/4
    mpz_add_ui(A, a, 2);
    mpz_cdiv_q_ui(A, A, 4);

    //B = Xn + Zn
    mpz_add(B, P.x, P.y);

    //C = Xn - Zn
    mpz_sub(C, P.x, P.y);

    //D = B² -> (Xn + Zn)²
    mpz_mul(D, B, B);

    //E = C² -> (Xn - Zn)²
    mpz_mul(E, C, C);

    //F = D-E -> (4*XnZn)
    mpz_sub(F, D, E);

    //G = A*F -> ((a + 2)/4)*(4*XnZn)
    mpz_mul(G, A, F);

    //void mpz_addmul !!!!!!!!!!!!!!!!!!!!!!

    //H = E+G -> (Xn - Zn)² + ((a + 2)/4)*(4*XnZn)
    mpz_add(H, E, G);

    //Calcula Ponto P2n(X2n : Z2n)
    //Ponto_mpz Pn; TESTAR!!!!!!!!!!!!!!!!!!!!!!!!!!!

    //X2n = (Xn + Zn)² * (Xn - Zn)²
    mpz_mul(Pn_x, D, E);

    //NECESSARIO???????????????
    //X2n % p
    mpz_mod(Pn_x, Pn_x, p);

    //Z2n = (4*XnZn)*((Xn - Zn)² + ((a + 2)/4)*(4*XnZn)) 
    mpz_mul(Pn_y, F, H);
    
    //NECESSITA????
    //Z2n % p
    mpz_mod(Pn_y, Pn_y, p);

    //Libera memoria alocada
    mpz_clears(A, B, C, D, E, F, G, H, NULL);

    return {Pn_x, Pn_y};

}

//5. Multiplicacao escalar chama 'ADD' com a condição de k existir (k shift até encerrar os bits)
//P1 sempre sera calculado pelo 'DOUBLE'
Ponto multiplicacao_escalar(mpz_t chave_prv, Ponto P){
    //Ponto P1 = 
    mpz_t x2, y2;
    mpz_init_set(x2, P.x);
    mpz_init_set(y2, P.y);


    //mpz_init_set_ui(x2, mpz_add(chave_prv, P.x));
    //mpz_init_set_ui(x2, mpz_add(chave_prv, P.y));

    //mpz_init_set_ui(x2, mpz_add_ui(chave_prv, 4));
    //mpz_init_set_ui(x2, mpz_add_ui(chave_prv, 3));

    return {x2, y2};
}

//6. Gerar um numero inteiro randomico no intervalo [1, n-1] e retorna uma CHAVE PRIVADA
void gera_int_rand(mpz_t chave_prv, const mpz_t n){
    
    //________________________INICIO GERAR SEMENTE________________________

    //Gera a semente sem bloqueio, diferente do /dev/random que pode bloquear se nao houver entropia suficiente
    //urandom eh seguro o suficiente, mas para criptografia eh garantido ultilizar random (porém pode haver bloqueio e demorar)
    ifstream urandom("/dev/urandom", ios::binary);
    if(!urandom){
        cerr << "Erro ao abrir /dev/urandom" << endl;
        return;
    }
    unsigned char seed[64];  //64 bytes de semente para C25519 (pode ser menor e seguro)

    uint64_t semente; //Teste com inteiro, declara int de 64 bits

    /*"64-bits of information to avoid repeating the same seed...
    ...If you read 4 bytes from this device then you will get a nicely random and unpredictable 32-bit seed
    value, and you can read as many bytes as you need." 
    (Good Practice in (Pseudo) Random Number Generation for Bioinformatics Applications
    David Jones, UCL Bioinformatics Group, 2010)*/
    urandom.read(reinterpret_cast<char*>(&seed), sizeof(seed)); //armazena em seed como char
    urandom.close();

    urandom.read(reinterpret_cast<char*>(&semente), sizeof(semente));
    urandom.close();

    cout << "\n**************INICIO FUNCAO 6******************\n" << endl;

    cout << "\n\nSeed: ";
    for(int i = 0; i < sizeof(seed); ++i){
        cout << hex << static_cast<int>(seed[i]);
    }
    cout << dec << endl;

    //Semente gerada em um inteiro
    cout << "\nTamanho da Seed: " << sizeof(seed) << endl;

    //Converte a semente char em mpz_t
    mpz_t conv_seed;
    mpz_init(conv_seed);
    mpz_import(conv_seed, sizeof(seed), 1, 1, 0, 0, seed); //convertendo de char para mpz_t
    gmp_printf("\nSemente convertida: %Zd ", conv_seed);

    //________________________FIM GERAR SEMENTE________________________

    //________________________INICIO GERAR STATE PELA SEMENTE________________________
    //Inicializar o gmp-state com default = mt (Mersenne Twister algorithm)
    gmp_randstate_t state;
    gmp_randinit_default(state); //necessita inicializar para ultilizar as demais funcoes (por defalut eh mt)

    //State inicializado em hexadecimal
    cout << "\n\nState: " << state; //STATE NAO EH UM NUMERO GMP, EH UM PONTEIRO!
    //Por isso ele mostra o endereco de memoria e necessita de cout, assim o valor nao eh alterado

    //COMO CONVERTER O ENDEREÇO DE MEMÓRIA PARA MOSTRAR O VALOR EM HEX OU DECIMAL??????

    //Cria uma chave privada, baseada no STATE sem SEED e no intervalo [1, n-1]
    mpz_urandomm(chave_prv, state, n); //n = 7237005577332262213973186563042994240857116359379907606001950938285454250989
    gmp_printf("\nChave privada 1 (sem seed): % Zd ", chave_prv);

    //Inicia o gerador de estado da GMP para ultilizar mpz_urandom com a semente fornecida
    gmp_randseed(state, conv_seed); //USAR O TIME _UI ou conv_seed1    
    cout << "\n\nState (com seed): " << state; //mantem o endereço de memoria, testar valor após conversão em hex ou deciamal
    
    //Gera uma nova chave privada baseada no STATE com SEED e no intervalo [1, n-1]
    mpz_urandomm(chave_prv, state, n);
    gmp_printf("\nChave privada 2 (com seed): % Zd ", chave_prv);

    //Teste para saber se a SEED alterou o STATE antes de iniciar
    //1 - Limpa o STATE
    //2 - Inicia novamente o STATE com a mesma funcao
    //3 - Mostra o que está no mesmo endereco de memoria
    //4 - Gera uma chave privada que é igual a SEM SEED anterior
    //5 - Mantem o mesmo endereco de memoria 
    //6 - Gera uma segunda chave privada SEM SEED e o resultado difere do anterior COM SEED
    
    //O teste foi realizado com tres chaves e constatou que ao alimentar o STATE com o SEED
    //ocorre sim uma mudança, pois se replicar apos reinicializacao do STATE os resustados sao identicos.
    //Assim, ao nao realimentar com SEED apos reinicializacao, o resultado difere, provando que a funcao
    //randseed altera o valor do STATE ao aplicar a SEED no intervalo de 'n'.
    
    //Limpa a memoria do state
    gmp_randclear(state);
    //Inicializa o state novamente
    gmp_randinit_default(state);

    //State inicializado em hexadecimal****REPETE TODO PROCESSO
    cout << "\n\nState*: " << state; //STATE NAO EH UM NUMERO GMP, EH UM PONTEIRO

    mpz_urandomm(chave_prv, state, n); //n = 7237005577332262213973186563042994240857116359379907606001950938285454250989
    gmp_printf("\nChave privada 1 (sem seed)*: % Zd ", chave_prv);

    //NAO ALIMENTA COM SEED
    
    //Mantem o mesmo endereco de memoria
    cout << "\n\nState (sem seed)*: " << state;
    
    //Mostra outra chave privada, ou seja, 
    mpz_urandomm(chave_prv, state, n);
    gmp_printf("\nChave privada 2 (SEM seed)*: % Zd ", chave_prv);

    //________________________FIM GERAR STATE PELA SEMENTE________________________

    do{
        //Gera um número aleatório no intervalo [1, ordem da curva - 1]
        mpz_urandomm(chave_prv, state, n);
        //mpz_add_ui(chave_prv, chave_prv, 1);  // Adiciona 1 para garantir que seja >= 1
   
    }while(mpz_cmp_ui(chave_prv, 1) <= 0);
    

    gmp_printf("\nChave privada TESTE: % Zd ", chave_prv);

    //Teste retorno add 1
    mpz_add_ui(chave_prv, chave_prv, 1);

    cout << "\n**************FIM FUNCAO 6******************\n" << endl;

    //Limpa a memoria do state
    gmp_randclear(state);
}

//7. Gera a CHAVE PUBLICA ultilizando a multiplicacao escalar da CHAVE PRIVADA com o Ponto base dado P1(x1,y1)
//Retorna P2(X2, Y2)???????????????
Ponto gera_chave_pbl(mpz_t chave_prv, Ponto P){
    return multiplicacao_escalar(chave_prv, {P.x, P.y});
}

/*NAO TESTADO
//8. Encripta a mensagem ultilizando a CHAVE PUBLICA
Ponto encriptar_mensagem(Ponto msg_cod, Ponto chave_pbl){
    
    return {};
}
*/

/*NAO TESTADO
//9. Decripta a mensagem ultilizando a CHAVE PRIVADA
void decriptar_mensagem(Ponto cifra, mpz_t chave_prv){
    
    //Ver encrip e encode!!!!!!!!!
}
*/

int main()
{
    //!!!!!!!!!!!!!!!!!!!!!!!!!TESTAR CUSTO COMPUTACIONAL VS PRECISÃO!!!!!!!!!!!!!!!!!!!!!!!!!!!

    //***********************Inicializa os parametros para C25519 de 128-bit de segurança***********************
    //Melhor iniciar na main() e passa via funcoes pois necessita inicializar e limpar a memoria sempre
    //cofator 8 ("has order h⋅n, where h=8 and where n is a prime number")

    //Numero primo fixo p = (2^255) - 19 = 5,789604462×10⁷⁶
    //p=0x7fffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffed
    mpz_init(p);
    mpz_ui_pow_ui(p, 2, 255);   
    mpz_sub_ui(p, p, 19);

    //Inteiro que A² - 4 nao eh raiz do modulo 'p' (A = 486662 ou 0x76d06)
    //"A2 792 −4 is not a square in GF(p), whereas A+2 is"  
    mpz_init_set_ui(a, 486662);

    //B = 1 ou 0x01, assim nao se faz necessario inicializar a memoria (Montgomery Curve -> By² = x³ + Ax² + x)
    //mpz_init_set_ui(b, 1);

    //Ordem da curva eliptica ou Fp² (n)
    //n = 2^(252) + 27742317777372353535851937790883648493
    //n: 7237005577332262213973186563042994240857116359379907606001950938285454250989 (=2^252 + 0x14def9de a2f79cd6 5812631a 5cf5d3ed)
    //CONFERIR 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    mpz_t n_var;
    mpz_init(n);
    //mpz_set_str(n, "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED", 16);
    mpz_init_set_str(n_var, "27742317777372353535851937790883648493", 10);
    mpz_ui_pow_ui(n, 2, 252);   
    mpz_add(n, n, n_var); //CONFERIR SE MULTIPLICOU O COFATOR 8!!!!!!!!!!!!!!!!!!

    //Ponto base definido por Daniel J. Bernstein Gu = 9 (=0x9)
    mpz_init_set_ui(x1, 9);
    
    //Sugestao para coordenada base y1
    //Gv = 43114425171068552920764898935933967039\370386198203806730763910166200978582548
    //(=0x5f51e65e 475f794b 1fe122d3 88b72eb3 6dc2b281 92839e4d d6163a5d 81312c14) 
    //CONFERIR 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    mpz_init_set_str(y_1, "14781619447589544791020593568409986887264606134616475288964881837755586237401", 10);

    //As funcoes ADD e DOUBLE para Curva25519 que eh uma Montgomery Curve (1987) com um numero primo fixo (p)
    //Um ponto racional P(x, y) eh representado em coordeenadas Montgomery P(X : Z), sendo x = X/Z para Z != 0
    //Assim, para pontos racionais temos: Pm(Xm : Zm) = [m]P(X : Z) e Pn(Xn : Zn) = [n]P(X : Z)

    //Inicia como zero o inteiro que receberah a mensagem para codificacao e a chave privada
    mpz_t mensagem, msg_des;
    mpz_inits(mensagem, msg_des, NULL);

    //Semente para gerar numero randomico da Chave Privada
    //mpz_t chave_prv, seed;
    //mpz_inits(chave_prv, seed, nullptr);
    mpz_t chave_prv;
    mpz_init_set_ui(chave_prv, 0);

    //*****************************************************************************
  
    //Valores iniciados da Curva25519
    gmp_printf ("\nValor P = % Zd ", p);
    gmp_printf ("\nValor A = % Zd ", a);
    //gmp_printf ("\nValor B = % Zd ", b);
    gmp_printf ("\nValor N = % Zd ", n);
    gmp_printf ("\nValor X1 = % Zd ", x1);
    gmp_printf ("\nValor Y1 = % Zd ", y_1);
    
    cout << "\nDigite a mensagem para codificacao ECC-25519: ";
    gmp_scanf("%Zd", mensagem); 
    gmp_printf("\nMensagem: % Zd ", mensagem);

    //Codifica a mensagem (inteiro) inserida (CONVERTER DE QUAISQUER CARACTER PARA INTEIRO!!!!!!!!!!!!!!!!)
    Ponto msg_cod = codifica_mensagem_para_ponto_da_c25519(mensagem);
    gmp_printf("\nMensagem Codificada\nx: % Zd e y: % Zd", msg_cod.x, msg_cod.y);

    //Gera a Chave Privada limitada pela ordem da curva eliptica (n), retornando inteiro
    gera_int_rand(chave_prv, n);
    gmp_printf("\nChave privada: % Zd ", chave_prv);

    //Gera a Chave Publica fornecendo a Chave Privada pela multiplicacao escalar ultilizando o ponto inicial (x1, y1)
    Ponto chave_pbl = gera_chave_pbl(chave_prv, {x1, y_1});
    gmp_printf("\n\nChave Publica: \nx: % Zd\ny: % Zd", chave_pbl.x, chave_pbl.y);

    //encriptar_mensagem(msg_cod, chave_pbl); //RETORNA UM VETOR DE PONTO??????
    //gmp_printf("\nMensagem criptografada\n C1: x = % Zd | y = % Zd", msg_crp.x, msg_crp.y); //DECLARAR !!!!!!!!!!!!!
    //gmp_printf("\nC2: x = % Zd | y = % Zd", msg_crp.x, msg_crp.y); //DECLARAR !!!!!!!!!!!!!

    //decriptar_mensagem(cifra, chave_prv);
    //gmp_printf("\nMensagem descriptografada: % Zd", msg_des);
    
    //Limpa variáveis para liberar memória
    //mpz_clear(h);
    //mpz_clear(b);
    mpz_clears(p, a, n, x1, y_1, n_var, mensagem, chave_prv, NULL);

    cout << endl << endl;
    //FIM DO CODIGO DE TESTE*/

    return 0;
}