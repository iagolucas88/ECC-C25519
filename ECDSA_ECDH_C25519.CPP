/*____________________________________________________________________________
Code developed by Iago Lucas (iagolbg@gmail.com | GitHub: iagolucas88)
for his master's degree in Mechatronic Engineering at the
Federal University of Rio Grande do Norte (Brazil).

Elliptic Curve Cryptography (ECC) for IoT devices
(microcontrollers) implementing Curve25519 (Daniel J. Bernstein).
____________________________________________________________________________*/

#include <iostream>
#include <gmp.h>
#include <fstream> //Para gerar seed pelo /dev/urandom

using namespace std;

// *****************Coordenada Afim******************* 
struct Ponto
{
    mpz_t x, y;
};

// Função para inicializar um ponto com valores mpz_t
void initPonto(Ponto &P, const mpz_t x_val, const mpz_t y_val)
{
    mpz_init_set(P.x, x_val);
    mpz_init_set(P.y, y_val);
}

// Função para inicializar um ponto sem valores específicos
void initPonto(Ponto &P)
{
    mpz_init(P.x);
    mpz_init(P.y);
}

// Função para limpar um ponto, liberando recursos
void clearPonto(Ponto &P)
{
    mpz_clear(P.x);
    mpz_clear(P.y);
}

// *****************Coordenada Projetiva*******************
// REMOVER E USAR APENAS UMA ESTRUTURA DE PONTO
struct P_projetivo
{
    mpz_t x, z;
};

// Função para inicializar um ponto com valores mpz_t
void initPontoP(P_projetivo &Pp, const mpz_t xp, const mpz_t zp)
{
    mpz_init_set(Pp.x, xp);
    mpz_init_set(Pp.z, zp);
}

// Função para inicializar um ponto sem valores específicos
void initPontoP(P_projetivo &Pp)
{
    mpz_init(Pp.x);
    mpz_init(Pp.z);
}

// Função para limpar um ponto, liberando recursos
void clearPontoP(P_projetivo &Pp)
{
    mpz_clear(Pp.x);
    mpz_clear(Pp.z);
}

//*******DECLARA GLOBALMENTE PARAMETROS CURVA ELIPTICA [E: y² = x² + a*x + b (mod p)]*********************
// E: curva eliptica no campo GF(q) onde |E| = h*n
// p: numero primo do campo | n: ordem da curva (numero primo enorme)| h: co-fator (numero pequeno, ex.: 1, 2, 4 ou 8)
// a, b: Curva de Weierstrass (Wa,b) onde 'a' e 'b' são elementos de GF(q) com 4a³ + 27b² != 0
// P0: ponto base (x0, y0) da curva (qualquer ponto da curva pode ser gerado pelo grupo ciclico <P> ={kP | k = 0,1,2,...} de E)
mpz_t p, n, a, a24, zero, one;
mpz_t P_0x, P_0y, z1;
// mpz_t h, b; //'h = 8' e 'b = 1' nao serao ultilizados, economizando memoria
Ponto P_0;

// 0. Inicializa os parametros da curva eliptica 'Curve25519' (E)
void inic_parametros_c25519()
{
    /*_______________________________________________________________________
        Inicializa os parametros para C25519 de 128-bit de segurança
    _________________________________________________________________________

    // B = 1, assim nao se faz necessario inicializar a memoria (Montgomery Curve -> By² = x³ + Ax² + x)
    // mpz_init_set_ui(b, 1);

    Cofator 8 ("has order h⋅n, where h=8 and where n is a prime number")
    */
    // Numero primo fixo p = (2^255) - 19 = 5,789604462×10⁷⁶
    mpz_init_set_str(p, "57896044618658097711785492504343953926634992332820282019728792003956564819949", 10); // p = 2^255 - 19
    // Ordem da curva eliptica ou Fp² (n): n = 2^(252) + 27742317777372353535851937790883648493
    mpz_init_set_str(n, "7237005577332262213973186563042994240857116359379907606001950938285454250989", 10); // n = 2^252 + 27742317777372353535851937790883648493
    // Inteiro que A² - 4 nao eh raiz do modulo 'p' (A = 486662 ou 0x76d06)
    mpz_init_set_ui(a, 486662);
    // a24 = (a + 2) / 4 = 121666
    mpz_init_set_ui(a24, 121666);

    // Ponto base da curva 'Curve25519' (E) definido por Daniel J. Bernstein Gu = 9 e
    // Gv = 43114425171068552920764898935933967039\370386198203806730763910166200978582548
    // o valor da coordenada y é pouco relevante para os calculos
    mpz_init_set_ui(P_0x, 9); //x0 = 9
    mpz_init_set_str(P_0y, "14781619447589544791020593568409986887264606134616475288964881837755586237401", 10); // y0 = 14781619447589544791020593568409986887264606134616475288964881837755586237401
    // y0 considerando x0 = 9 (correto pela raiz quadrada modular)
    mpz_init_set_ui(z1, 1); // z1 = 1

    // Inicializa o ponto base da curva 'Curve25519' (E)
    initPonto(P_0, P_0x, P_0y);

    // Inicializa constantes 0 e 1
    mpz_init_set_ui(zero, 0);
    mpz_init_set_ui(one, 1);
}

// 1. Converte qualquer caracter para inteiro GMP (tabela ASCII)
void string_to_mpz(const string &mensagem, mpz_t msg_convertida)
{
    mpz_t int_caractere;
    mpz_init(int_caractere);
    mpz_init_set(msg_convertida, zero);

    for (size_t i = 0; i < mensagem.length(); ++i)
    {
        unsigned char c = mensagem[i];
        mpz_ui_pow_ui(int_caractere, 256, i);        // 256^i
        mpz_mul_ui(int_caractere, int_caractere, c); // (256^i) * valor ASCII do caractere
        mpz_add(msg_convertida, msg_convertida, int_caractere);
    }
}

// Função para calcular o símbolo de Legendre
int legendre_simbolo(const mpz_t a, const mpz_t p)
{
    mpz_t result;
    mpz_init_set(result, p);

    mpz_sub_ui(result, result, 1);
    mpz_divexact_ui(result, result, 2);
    mpz_powm(result, a, result, p);

    int legendre = mpz_cmp_ui(result, 1) == 0 ? 1 : (mpz_cmp_ui(result, 0) == 0 ? 0 : -1);
    mpz_clear(result);
    return legendre;
}

// Função para calcular a raiz quadrada modular usando o algoritmo de Tonelli-Shanks
void raiz_quadrada_modular(mpz_t &result, mpz_t a, mpz_t p){
    if (legendre_simbolo(a, p) != 1)
    {
        cout << "Não há raiz quadrada!" << endl;
    }

    mpz_t q, s, z, m, c, t, r, b, temp;
    mpz_inits(q, s, z, m, c, t, r, b, temp, NULL);

    mpz_sub_ui(q, p, 1);
    mpz_set_ui(s, 0);

    while (mpz_even_p(q))
    {
        mpz_fdiv_q_2exp(q, q, 1);
        mpz_add_ui(s, s, 1);
    }

    mpz_set_ui(z, 2);

    while (legendre_simbolo(z, p) != -1)
    {
        mpz_add_ui(z, z, 1);
    }

    mpz_powm(c, z, q, p);

    mpz_add_ui(temp, q, 1);
    mpz_divexact_ui(temp, temp, 2);
    mpz_powm(r, a, temp, p);

    mpz_powm(t, a, q, p);
    mpz_set(m, s);

    while (mpz_cmp_ui(t, 1) != 0)
    {
        mpz_set_ui(temp, 1);
        mpz_set_ui(b, 2);
        while (mpz_cmp_ui(temp, 1) != 0)
        {
            mpz_powm(temp, t, b, p);
            mpz_add_ui(b, b, 1);
        }

        mpz_sub_ui(temp, m, mpz_get_ui(b));
        mpz_sub_ui(temp, temp, 1);
        mpz_powm_ui(temp, c, mpz_get_ui(temp), p);
        mpz_mul(c, temp, temp);
        mpz_mod(c, c, p);
        mpz_mul(r, r, temp);
        mpz_mod(r, r, p);
        mpz_mul(t, t, c);
        mpz_mod(t, t, p);
        mpz_set(m, b);
    }

    mpz_set(result, r);

    mpz_clears(q, s, z, m, c, t, r, b, temp, NULL);
}

// 2. Codifica a mensagem para os pontos na curva 'Curve25519' (E)
Ponto codifica_mensagem_para_ponto_da_c25519(mpz_t msg){

    mpz_t x_msg, y_msg, y_msg_squared, var, exp_euler;
    mpz_inits(x_msg, y_msg, y_msg_squared, var, exp_euler, NULL);

    // Necessario copiar para nao alterar o valor da mensagem original e evitar conflitos
    mpz_set(x_msg, msg);

    // Multiplica por 100 para garantir no Teste de Euler as adições sejam descartadas
    mpz_mul_ui(x_msg, x_msg, 100); // x_msg = msg * 100

    Ponto P_msg;
    initPonto(P_msg, x_msg, y_msg); // Inicializa o ponto P_msg

    // gmp_printf("x_msg: %Zd", x_msg);

    //COMO p EH CONHECIDO, COLOCAR RESULTADO DIRETO
    // Expoente para o Teste de Euler: exp_euler = (p-1)/2
    mpz_sub_ui(exp_euler, p, 1);
    mpz_cdiv_q_ui(exp_euler, exp_euler, 2);
    //gmp_printf("\nExpoente do Teste de Euler: %Zd", exp_euler); // CALCULAR RESULTADO E INSERIR NOS PARAMETROS INICIAIS

    while(true){
        // y² = x³ + a*x² + x  mod p
        mpz_powm_ui(var, x_msg, 2, p);              // x²
        mpz_mul(var, var, a);                       // a*x²
        mpz_add(y_msg_squared, var, x_msg);         // a*x² + x
        mpz_powm_ui(var, x_msg, 3, p);              // x³
        mpz_add(y_msg_squared, y_msg_squared, var); // x³ + a*x² + x
        mpz_mod(y_msg_squared, y_msg_squared, p);   // y² = x³ + a*x² + x  mod p

        //gmp_printf("\n\ny²: %Zd", y_msg_squared);

        // Teste de Euler: verifica se y² é um resíduo quadrático
        mpz_powm(y_msg, y_msg_squared, exp_euler, p); // y^2*[(p-1)/2]  mod p
        // gmp_printf("\ny_msg: %Zd", y_msg);

        // Verifica se y^2 eh residuo quadratico (mod prime)
        if (mpz_cmp_ui(y_msg, 1) == 0)
        {
            raiz_quadrada_modular(y_msg, y_msg_squared, p);
            break;
        }

        else
            mpz_add_ui(x_msg, x_msg, 1); // Incrementa x e tenta novamente
    }
    // Define o ponto P_msg
    mpz_set(P_msg.x, x_msg);
    mpz_set(P_msg.y, y_msg);

    //gmp_printf("\n\nPonto codificado:\nx: %Zd\ny: %Zd", P_msg.x, P_msg.y);

    // Limpa variáveis temporárias
    mpz_clears(x_msg, y_msg, y_msg_squared, var, exp_euler, NULL);

    return P_msg;
}

void validacao_ponto(Ponto &Q){
    // Variaveis utilizadas no Teste 3: equacao da curva By² = x³ + Ax² + x
    mpz_t le, ld, var;
    mpz_inits(le, ld, var, NULL);

    initPonto(Q, Q.x, Q.y); // Inicializa o ponto Q

    // Lado esquerdo da equacao (B = 1)
    mpz_powm_ui(le, Q.y, 2, p); // y² mod p
    gmp_printf("\n\ny²:           %Zd", le);

    // Lado direito da equacao
    mpz_powm_ui(ld, Q.x, 2, p); // x² mod p
    mpz_mul(var, a, ld);        // ax²
    mpz_powm_ui(ld, Q.x, 3, p); // x³ mod p
    mpz_add(ld, ld, var);       // x³ + ax²
    mpz_add(ld, ld, Q.x);       // x³ + ax² + x
    mpz_mod(ld, ld, p);         // x³ + ax² + x mod p
    gmp_printf("\nx³ + ax² + x: %Zd", ld);

    // Teste 1: Q eh um ponto no infinito
    if (Q.x == 0 && Q.y == 0)
        cout << "\nREJEITADO (Q eh ponto no infinito)" << endl;

    // Teste 2: 0 <= (x, y) ou (u, v) <= (p - 1)
    else if (Q.x >= zero && Q.x < p && Q.y >= zero && Q.y < p)
        cout << "\nREJEITADO (u e v fora do intervalo [0, p-1])" << endl;

    // Teste 3: By² = x³ + Ax² + x
    else if (mpz_cmp(le, ld) != 0)
        cout << "\nREJEITADO (u e v nao satisfaz a equacao)" << endl;

    /*Para o teste completo, fazer apenas para chave pública e evitar loops
    // Teste 4: nQ eh um ponto no infinito
    else if
    {

    }*/

    else
        cout << "\nACEITO" << endl;

}

void double_add_ponto(P_projetivo &R0, P_projetivo &R1)
{
    /*_________________________________________________________________________________________________
        FORMULAS RETIRADAS DO TEOREMA B2 DO APENDIX B (pag. 228)
        Curve25519: New Diﬃe-Hellman Speed Records

        Coordenadas: Afins (x, y) --> (X:Y:1) Projetiva
                Projetiva (X:Y:Z) --> (x/z, y/z, 1) Afins

        Apenas faz-se necessário ultilizar a coordenada x, assim:
            X(Q + Q') = x3/z3 para todo Q e Q' pertencentes ao campo E(Fp²), onde
            X(Q) = x/z, X(Q') = x'/z' e X(Q - Q') = x1/z1
        Considerando x1 = 9 e z1 = 1 (pode ser qualquer numero diferente de zero, o valor 1 simplifica os cálculos)
    ___________________________________________________________________________________________________*/

    mpz_t A, B, C, D, E, F;
    mpz_inits(A, B, C, D, E, F, NULL);

    // Cálculos comuns de Duplicação
    mpz_add(A, R0.x, R0.z); // A = x + z
    mpz_sub(B, R0.x, R0.z); // B = x - z

    // DOUBLE
    // R0.x = x2 = (x² - z²)² mod p = (x - z)²*(x + z)² mod p
    // R0.z = z2 = 4*x*z*(x² + a*x*z + z²) mod p = ((x + z)² - (x - z)²*((x + z)² + ((a-2)/4)*((x + z)² - (x - z)²))) mod p
        
    // Caso 1: z = 0, então x2 = x⁴ != 0 e z2 = 0, temos X(2Q) = 0 (ponto no infinito)
    if (mpz_cmp(R0.z, zero) == 0) {
        cout << "\nDOUBLE: R0.z = 0, X(2Q) = 0 (ponto no infinito)" << endl;
        mpz_set(R0.x, one);
        mpz_set(R0.z, zero);
    }

    // Caso 2: z != 0 e x = 0, entao x2 = z⁴ != 0 e z2 = 0, temos X(2Q) = 0 (ponto no infinito)
    else if (mpz_cmp_ui(R0.x, 0) == 0) {
        cout << "\nDOUBLE: R0.x = 0, X(2Q) = 0 (ponto no infinito)" << endl;
        mpz_set(R0.x, one);
        mpz_set(R0.z, zero);
    }

    // Caso 3: x != 0 e z != 0, entao Q = (x/z, y/z, 1) 'AFINS', temos X(2Q) = x2/z2
    else {
        // Duplicação de R0 cálculos comuns
        mpz_mul(E, B, B);       // E = (x - z)²
        mpz_mul(F, A, A);       // F = (x + z)²

        // R0.x = x2 = (x - z)²*(x + z)² mod p
        mpz_mul(R0.x, E, F);    // R0.x = (x - z)² * (x + z)²
        mpz_mod(R0.x, R0.x, p); // R0.x = (x - z)² * (x + z)² mod p

        // R0.z = z2 = ((x + z)² - (x - z)²*((x + z)² + ((a-2)/4)*((x + z)² - (x - z)²))) mod p
        mpz_sub(R0.z, F, E);       // R0.z = (x + z)² - (x - z)²
        mpz_mul(R1.x, a24, R0.z);  // R1.x = ((a + 2)/4)*((x + z)² - (x - z)²)  [ultiliza R1.x para economia de memória]
        mpz_add(R1.x, F, R1.x);    // R1.x = (x + z)² + ((a + 2)/4)*((x + z)² - (x - z)²)
        mpz_mul(R0.z, R0.z, R1.x); // R0.z = ((x + z)² - (x - z)²)*((x + z)² + ((a + 2)/4)*((x + z)² - (x - z)²))
        mpz_mod(R0.z, R0.z, p);    // R0.z = ((x + z)² - (x - z)²)*((x + z)² + ((a + 2)/4)*((x + z)² - (x - z)²)) mod p

        //gmp_printf("\n\nR0:(%Zd, %Zd)", R0.x, R0.z);
    }

    // ADD
    // R1.x = x3 = 4*z1(x*x' - z*z')² mod p = ((x - z)*(x' + z') + (x + z)*(x' + z'))²*z1 mod p
    // R1.z = z3 = 4*x1(x*z' - z*x')² mod p = ((x - z)*(x' + z') - (x + z)*(x' + z'))²*x1 mod p

    // Caso 1: Q = Q', logo X(Q - Q') = X(0) = 0 (ponto no infinito)
    if (mpz_cmp(R0.x, R1.x) == 0 && mpz_cmp(R0.z, R1.z) == 0) {
        //cout << "\nADD: Q = Q', X(Q - Q') = 0 = R1 (ponto no infinito)" << endl;
        mpz_set(R1.x, one);
        mpz_set(R1.z, zero);
    }

    // Caso 2: Q = 0, logo X(Q') = X(Q + Q')
    else if (mpz_cmp(R0.z, zero) == 0 && mpz_cmp(R0.x, zero) != 0 && mpz_cmp(R1.x, zero) != 0 && mpz_cmp(R1.z, zero) != 0) {
        //cout << "\nADD: Q = 0, X(Q') = X(Q + Q')" << endl;
    }

    // Caso 3: Q' = 0, logo X(Q) = X(Q + Q')
    else if (mpz_cmp(R1.z, zero) == 0 && mpz_cmp(R1.x, zero) != 0 && mpz_cmp(R0.x, zero) != 0 && mpz_cmp(R0.z, zero) != 0) {
        mpz_set(R1.x, R0.x);
        mpz_set(R1.z, R0.z);
        //cout << "\nADD: Q' = 0, X(Q) = X(Q + Q'), R1 = R0" << endl;
    }

    // Caso 4: Q = -Q', logo X(0) = X(Q + Q') (ponto no infinito)
    else if (mpz_cmp(R0.x, R1.x) == 0 && mpz_cmp(R0.z, R1.z) != 0) {
        //cout << "\nADD: Q = -Q', X(0) = X(Q + Q') (ponto no infinito)" << endl;
        mpz_set(R1.x, one);
        mpz_set(R1.z, zero);
    }

    // Caso geral: Q != Q' e Q != -Q', X(Q + Q') = x3/z3, z1 = 1 desconsidera nos calculos
    else {         
        // Cálculos comuns de Adição
        mpz_add(C, R1.x, R1.z); // C = x' + z'
        mpz_sub(D, R1.x, R1.z); // D = x' - z'
        
        // Adição de R1 cálculos comuns (P = (x1, z1) = (9, 1))
        mpz_mul(E, B, C);       // E = (x - z)*(x' + z')
        mpz_mul(F, A, D);       // F = (x + z)*(x' - z')

        //R1.x = x3 = ((x - z)*(x' + z') + (x + z)*(x' + z'))²*z1 mod p 
        mpz_add(R1.x, E, F);       // R1.x = (x - z)*(x' + z') + (x + z)*(x' + z')
        mpz_mul(R1.x, R1.x, R1.x); // R1.x = ((x - z)*(x' + z') + (x + z)*(x' + z'))²
        mpz_mod(R1.x, R1.x, p);    // R1.x = ((x - z)*(x' + z') + (x + z)*(x' + z'))² mod p

        //R1.z = z3 = ((x - z)*(x' + z') - (x + z)*(x' + z'))²*x1 mod p
        mpz_sub(R1.z, E, F);        // R1.z = (x - z)*(x' + z') - (x + z)*(x' + z')
        mpz_mul(R1.z, R1.z, R1.z);  // R1.z = ((x - z)*(x' + z') - (x + z)*(x' + z'))²
        mpz_mul(R1.z, R1.z, P_0.x); // R1.z = ((x - z)*(x' + z') - (x + z)*(x' + z'))²*x1
        mpz_mod(R1.z, R1.z, p);     // R1.z = ((x - z)*(x' + z') - (x + z)*(x' + z'))²*x1 mod p

        //gmp_printf("\n\nR1:(%Zd, %Zd)", R1.x, R1.z);
    }
    mpz_clears(A, B, C, D, E, F, NULL);
}

void conv_coord_proj_to_afim(mpz_t &cood_afim, P_projetivo &Pp) {
    mpz_t inv;
    mpz_init(inv);

    // Calcula o inverso modular do divisor: Z_inv = Z^(p-2) mod p
    if (mpz_invert(inv, Pp.z, p) == 0)
    {
        cout << "Divisor não tem inverso modular." << endl;
        mpz_clear(inv);
        return; // Encerra a função imediatamente
    }

    // Multiplica o dividendo pelo inverso modular: x = X * Z_inv mod p
    mpz_mul(cood_afim, Pp.x, inv);
    mpz_mod(cood_afim, cood_afim, p);

    mpz_clear(inv);
}

void swap_condicional(P_projetivo &R0, P_projetivo &R1, int &bit_cond) {
    if (bit_cond) {
        mpz_swap(R0.x, R1.x);
        mpz_swap(R0.z, R1.z);
        //gmp_printf("\n\nSwap condicional\nR0:(%Zd, %Zd)\nR1:(%Zd, %Zd)\n", R0.x, R0.z, R1.x, R1.z);
    }
}

// 5. Multiplicacao de um ponto por um escalar (k*P)
void multiplicacao_escalar(mpz_t &coord_x_afim, const mpz_t &k_rand, const mpz_t &coord_x)
{
    cout << "\n\n__________________________Mult Escalar______________________________\n" << endl; // REMOVER

    // Para não alterar o valor original de k_rand
    mpz_t k_var;
    mpz_init_set(k_var, k_rand);

    // Deve-se iniciar R0 = (1, 0) e R1 = 2P 
    // Para garantir a simetricidade com swap condicional para evitar ataques de canal lateral garantindo o constant-time
    P_projetivo R0, R1;
    initPontoP(R0, one, zero);  // Ponto neutro em coodenadas projetivas (1, 0)
    gmp_printf("\nR0 = O: (%Zd, %Zd)", R0.x, R0.z);
    
    initPontoP(R1, P_0.x, one); // R1 = R0 = P
    gmp_printf("\nR1 = P: (%Zd, %Zd)", R1.x, R1.z);
    
    //validacao_ponto(R1);

    // Verifica se k é 0
    if (mpz_cmp_ui(k_var, 0) == 0)
    {
        gmp_printf("\nk = 0\nx: % Zd", R1.x); // Apenas x eh necessario para a chave publica

        clearPontoP(R0); // Limpa o ponto R0

        conv_coord_proj_to_afim(coord_x_afim, R1); // Retorna o quociente da divisao de R1.x/R1.z
    }

    else{
        mpz_t k_bit, tam;
        mpz_inits(k_bit, tam, NULL);

        mpz_set_ui(k_bit, mpz_sizeinbase(k_var, 2)); // Número de bits de k

        for (mpz_sub(tam, k_bit, one); mpz_cmp(tam, zero) >= 0; mpz_sub(tam, tam, one))
        {
            int bit = mpz_tstbit(k_var, mpz_get_ui(tam)-1);
            
            //gmp_printf("\n\ntam: %Zd", tam);
            //gmp_printf("\nk_bit: %Zd", k_bit);
            //cout << "\nBIT: " << bit << endl;

            // Swap condicional se bit = 1
            swap_condicional(R0, R1, bit);

            // R0 = 2R0 e R1 = R0 + R1
            double_add_ponto(R0, R1);

            // Swap condicinal para restaurar a ordem original
            swap_condicional(R0, R1, bit);
        }

        clearPontoP(R1); // Limpa o ponto R1
        mpz_clears(k_bit, tam, NULL); // Limpa as variáveis temporárias

        cout << "\n\n________________________FIM Mult Escalar____________________________\n" << endl;

        // Retorna coordenada afim x = R0.x/R0.z, necessário divisão modular
        conv_coord_proj_to_afim(coord_x_afim, R0);
    }
}

// 6. Gerar um numero inteiro randomico no intervalo [1, n-1] e retorna uma CHAVE PRIVADA (k)
void gera_escalar_rand(mpz_t &k)
{
    // ________________________INICIO GERAR SEMENTE________________________
    // Gera a semente sem bloqueio, diferente do /dev/random que pode bloquear se nao houver entropia suficiente
    // urandom eh seguro o suficiente, mas para criptografia eh garantido ultilizar random (porém pode haver bloqueio e demorar)
    ifstream urandom("/dev/urandom", ios::binary);
    if(!urandom)
        cout << "Erro ao abrir /dev/urandom" << endl;

    unsigned char seed[64]; // 64 bytes de semente para C25519 (pode ser menor e seguro)

    /*"64-bits of information to avoid repeating the same seed...
    ...If you read 4 bytes from this device then you will get a nicely random and unpredictable 32-bit seed
    value, and you can read as many bytes as you need."
    (Good Practice in (Pseudo) Random Number Generation for Bioinformatics Applications
    David Jones, UCL Bioinformatics Group, 2010)*/
    urandom.read(reinterpret_cast<char *>(&seed), sizeof(seed)); // armazena em seed como char
    urandom.close();

/*
    cout << "Seed: ";
    for(int i = 0; i < sizeof(seed); ++i){
        cout << hex << static_cast<int>(seed[i]);
    }
    cout << dec << endl;
*/

    // Converte a semente char em mpz_t
    mpz_t conv_seed;
    mpz_init(conv_seed);
    mpz_import(conv_seed, sizeof(seed), 1, 1, 0, 0, seed); // convertendo char para mpz_t
    // gmp_printf("\nSemente convertida: %Zd ", conv_seed);

    // ________________________FIM GERAR SEMENTE________________________

    // ________________________INICIO GERAR STATE________________________
    // Inicializar o gmp-state com default = mt (Mersenne Twister algorithm)
    gmp_randstate_t state;
    gmp_randinit_default(state); // necessita inicializar para ultilizar as demais funcoes (por defalut eh mt)

    // Inicia o gerador de estado da GMP para ultilizar mpz_urandom com a semente fornecida
    gmp_randseed(state, conv_seed); // state eh um endereco de memoria

    // ________________________FIM GERAR STATE________________________

    // Gera uma escalar inteiro impar baseada no STATE com SEED no intervalo [1, n-1]
    do {mpz_urandomm(k, state, n);
    } while(mpz_cmp_ui(k, 1) <= 0 || mpz_even_p(k) != 0); // Enquanto k <= 1 ou k é par

    //gmp_printf("\n\nEscalar randomico (k): % Zd ", k);

    // Limpa as memorias
    mpz_clear(conv_seed);
    gmp_randclear(state);
}

void hmac(mpz_t &result, const mpz_t &key, const mpz_t &data) {
    // Implementação simples de HMAC usando GMP
    mpz_t temp;
    mpz_init(temp);
    mpz_xor(temp, key, data); // Exemplo simples de HMAC: XOR do valor
    mpz_add_ui(result, temp, 12345); // Adiciona um valor constante para mais complexidade
    mpz_clear(temp);
}

// PODE RETIRAR COLOCANTO DIRETO O hmac
void hkdf_extract(mpz_t &prk, const mpz_t &salt, const mpz_t &ikm) {
    // HKDF Extract: PRK = HMAC(salt, IKM)
    hmac(prk, salt, ikm);
}

void hkdf_expand(mpz_t &okm, const mpz_t &prk, const mpz_t &info, size_t length) {
    // HKDF Expand: OKM = HMAC-Expand(PRK, info, length)
    mpz_t temp;
    mpz_init(temp);
    hmac(temp, prk, info);
    mpz_mod_2exp(okm, temp, length * 8); // Trunca para o comprimento desejado
    mpz_clear(temp);
}

// 8. Encripta a mensagem ultilizando a CHAVE PUBLICA
void encriptar_mensagem(Ponto &msg_cod, mpz_t &chave_pbl, mpz_t &C1, mpz_t &C2, mpz_t &chave_prv_efemera){
    cout << "\n\n____________________________ENCRYPT________________________________\n" << endl; // REMOVER

    //mpz_t chave_prv_efemera, chv_compartilhada, chave_simetrica;
    //mpz_inits(chave_prv_efemera, chv_compartilhada, chave_simetrica, NULL);
    mpz_t chv_compartilhada, chave_simetrica;
    mpz_inits(chv_compartilhada, chave_simetrica, NULL);

    //gera_escalar_rand(chave_prv_efemera); // Gera uma chave privada efemera
    //mpz_mul_ui(chave_prv_efemera, chave_prv_efemera, 23);
    //gmp_printf("\nChave Privada Efemera: %Zd", chave_prv_efemera);
    //mpz_set(chave_prv_efemera, chave_prv_efemera);

    // C1 = k*P_0.x
    multiplicacao_escalar(C1, chave_prv_efemera, P_0.x);

    multiplicacao_escalar(chv_compartilhada, chave_prv_efemera, chave_pbl); // k*Pb.x   

    mpz_t prk;
    mpz_init(prk);
    hkdf_extract(prk, chave_prv_efemera, chv_compartilhada);
    hkdf_expand(chave_simetrica, prk, chave_prv_efemera, mpz_sizeinbase(msg_cod.x, 2) / 8); // Tamanho da mensagem em bytes

    mpz_xor(C2, msg_cod.x, chave_simetrica); // C2 = Pm XOR k*Pb

    mpz_clears(chv_compartilhada, chave_simetrica, NULL);
    cout << "\n\n________________________FIM ENCRYPT________________________________\n" << endl; // REMOVER
}

// 9. Decripta a mensagem ultilizando a CHAVE PRIVADA
void decriptar_mensagem(mpz_t &msg_dec, mpz_t &C1, mpz_t &C2, mpz_t &chave_prv){
    cout << "\n\n____________________________DECRYPT________________________________\n" << endl; // REMOVER

    mpz_t chv_compartilhada, chave_simetrica;
    mpz_inits(chv_compartilhada, chave_simetrica, NULL);

    multiplicacao_escalar(chv_compartilhada, chave_prv, C1); // k*C1.x

    // Deriva uma chave de criptografia simétrica a partir da chave compartilhada usando HKDF
    mpz_t prk;
    mpz_init(prk);
    hkdf_extract(prk, chave_prv, chv_compartilhada);
    hkdf_expand(chave_simetrica, prk, chave_prv, mpz_sizeinbase(C2, 2) / 8); // Tamanho da mensagem em bytes

    mpz_xor(msg_dec, C2, chave_simetrica); // Pm = C2 XOR k*C1

    mpz_clears(chv_compartilhada, chave_simetrica, NULL);
    cout << "\n___________________________FIM DECRYPT____________________________\n" << endl; // REMOVER
}

// 10. Decodifica a mensagem para string
void decodifica_ponto_para_string(mpz_t &msg_x){
    mpz_t var, var_1;
    mpz_inits(var, var_1, NULL);

    mpz_set(var, msg_x);
    mpz_tdiv_q_ui(var, var, 100); // Divide por 100 para obter a mensagem original

    string mensagem;
    char c;
    while(mpz_cmp_ui(var, 0) > 0){
        mpz_tdiv_r_ui(var_1, var, 256); // var_1 = var % 256
        c = mpz_get_ui(var_1);          // converte para char
        mensagem.push_back(c);          // adiciona o char na string
        mpz_tdiv_q_ui(var, var, 256);   // var = var / 256
    }

    cout << "\n\nMensagem Decodificada: ";
    for(int i = 0; i < mensagem.length(); ++i){
        cout << mensagem[i];
    }
    cout << endl;

    mpz_clears(var, var_1, NULL);
}

int main(){
    //!!!!!!!!!!!!!!!!!!!!!!!!!TESTAR CUSTO COMPUTACIONAL VS PRECISÃO!!!!!!!!!!!!!!!!!!!!!!!!!!!

    inic_parametros_c25519(); // Inicializa os parametros da curva eliptica C25519

    // Inicia como zero para evitar lixo de memória
    mpz_t msg_t_gmp, chave_prv, chave_pbl, k, msg_dec, C1, C2;
    mpz_inits(msg_t_gmp, chave_prv, chave_pbl, k, msg_dec, C1, C2, NULL);

    // Valores iniciados da Curva25519
    cout << "\n____________________________PARAMETROS CURVA 25519____________________________" << endl;
    gmp_printf("\np  = % Zd ", p);
    gmp_printf("\na  = % Zd ", a);
    // gmp_printf ("\nB = % Zd ", b);
    gmp_printf("\nn  = % Zd ", n);
    gmp_printf("\nx0 = % Zd ", P_0x);
    gmp_printf("\ny0 = % Zd ", P_0y);
    cout << "\n______________________________________________________________________________" << endl;

    string mensagem;
    cout << "\nDigite a mensagem para codificacao ECC-25519: ";
    cin >> mensagem;

    // Converte a mensagem para inteiro GMP
    string_to_mpz(mensagem, msg_t_gmp);
    gmp_printf("\nMensagem em inteiro (GMP): %Zd \n", msg_t_gmp);

    // TROCA DE CHAVES DIFFIE-HELLMAN  

    // Codifica a mensagem (inteiro) inserida para um ponto na curva eliptica C25519
    Ponto msg_cod = codifica_mensagem_para_ponto_da_c25519(msg_t_gmp);
    gmp_printf("\n\nMensagem Codificada\nx: % Zd\ny: % Zd", msg_cod.x, msg_cod.y);

    // Gera a Chave Privada (k) limitada pela ordem da curva eliptica (n), retornando inteiro
    gera_escalar_rand(chave_prv);
    gmp_printf("\n\nChave Privada: % Zd ", chave_prv);

    // Gera a Chave Publica fornecendo a Chave Privada
    // pela multiplicacao escalar ultilizando a coordenada x do ponto inicial (x1)
    multiplicacao_escalar(chave_pbl, chave_prv, P_0.x);
    gmp_printf("\n\nChave Publica (x = X/Z): % Zd", chave_pbl);

    // ASSINATURA DIGITAL (ENCRYPT E DECRYPT) ECDH

    mpz_t chave_prv_efemera;
    mpz_init(chave_prv_efemera);
    gera_escalar_rand(chave_prv_efemera); // Gera uma chave privada efemera
    mpz_mul_ui(chave_prv_efemera, chave_prv_efemera, 23);
    gmp_printf("\nChave Privada Efemera: %Zd", chave_prv_efemera);

    // Encripta a mensagem ultilizando a Chave Publica
    encriptar_mensagem(msg_cod, chave_pbl, C1, C2, chave_prv_efemera);
    gmp_printf("\n\nMensagem criptografada\nC1: %Zd", C1);
    gmp_printf("\nC2: %Zd", C2);

    // Decripta a mensagem ultilizando a Chave Privada
    decriptar_mensagem(msg_dec, C1, C2, chave_prv_efemera);
    gmp_printf("\n\nMensagem descriptografada (x): %Zd", msg_dec);

    // Decodifica a mensagem para string original
    decodifica_ponto_para_string(msg_dec);

    // Limpa variáveis para liberar memória
    // mpz_clears(h, b, NULL);
    mpz_clears(p, a, n, P_0x, P_0y, msg_t_gmp, chave_prv, k, chave_pbl, msg_dec, C1, C2, NULL);
    cout << endl << endl;
    
    return 0;
}