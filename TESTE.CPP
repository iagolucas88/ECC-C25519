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

struct Ponto{
    mpz_t x, y;
};

// Função para inicializar um ponto com valores mpz_t
void initPonto(Ponto& P, const mpz_t x_val, const mpz_t y_val) {
    mpz_init_set(P.x, x_val);
    mpz_init_set(P.y, y_val);
}

// Função para inicializar um ponto sem valores específicos
void initPonto(Ponto& P) {
    mpz_init(P.x);
    mpz_init(P.y);
}

// Função para limpar um ponto, liberando recursos
void clearPonto(Ponto& P) {
    mpz_clear(P.x);
    mpz_clear(P.y);
}

//*******DECLARA GLOBALMENTE PARAMETROS CURVA ELIPTICA [E: y² = x² + a*x + b (mod p)]*********************
// E: curva eliptica no campo GF(q) onde |E| = h*n
// p: numero primo do campo | n: ordem da curva (numero primo enorme)| h: co-fator (numero pequeno)
// a, b: Curva de Weierstrass (Wa,b) onde 'a' e 'b' são elementos de GF(q) com 4a³ + 27b² != 0
// P0: ponto base (x0, y0) da curva (qualquer ponto da curva pode ser gerado pelo grupo ciclico <P> ={kP | k = 0,1,2,...} de E)
mpz_t p, n, a, a24;
mpz_t P_0x, P_0y;
// mpz_t h, b; //'h' e 'b' nao serao ultilizados, economizando memoria
Ponto P_0;

// 1. Converte qualquer caracter para inteiro GMP (tabela ASCII)
void string_to_mpz(const string &mensagem, mpz_t msg_convertida){
    mpz_t int_caractere;
    mpz_init(int_caractere);
    mpz_init_set_ui(msg_convertida, 0);

    for (size_t i = 0; i < mensagem.length(); ++i)
    {
        unsigned char c = mensagem[i];
        mpz_ui_pow_ui(int_caractere, 256, i);        // 256^i
        mpz_mul_ui(int_caractere, int_caractere, c); // (256^i) * valor ASCII do caractere
        mpz_add(msg_convertida, msg_convertida, int_caractere);
    }

    mpz_clear(int_caractere);
}

// 1. Curva eliptica 'Curve25519' (E). Mod q
// Codifica a mensagem para os pontos na curva ultilizada.
Ponto codifica_mensagem_para_ponto_da_c25519(mpz_t msg){

    mpz_t x_msg, y_msg, c25519_msg, A, B, C, exp_euler, teste_euler;
    mpz_inits(x_msg, y_msg, c25519_msg, A, B, C, exp_euler, teste_euler, NULL);

    // Necessario copiar para nao alterar o valor da mensagem original e evitar conflitos
    mpz_set(x_msg, msg);

    Ponto P_msg;
    initPonto(P_msg, x_msg, y_msg); // Inicializa o ponto P_msg

    std::cout << "\n____________________________MSG PARA PONTO________________________________\n" << endl; // REMOVER

    // Armazena a quantidade de digitos da mensagem na base 10
    int tamanho_msg = mpz_sizeinbase(msg, 10);
    int dif_digitos = 0;
    // cout << "\nQuantidade de digitos da mensagem: " << tamanho_msg << endl;

    // Diferenca de digitos para inserir zeros no 'x_msg'
    dif_digitos = 99 - tamanho_msg;

    if (dif_digitos > 0)
    {
        // Multiplica a mensagem até 99 vezes a quantidade de digitos
        // para garantir que sejam maior que p (aprox 76 digitos)
        for (int i = 0; i < dif_digitos; i++)
        {
            mpz_mul_ui(x_msg, x_msg, 10);
        }
        // Mensagem estendida para efetuar os calculos
        gmp_printf("x_msg: %Zd", x_msg);
    }
    else
        gmp_printf("x_msg: %Zd", x_msg);

    /*
        //Teste de Euler [y^((p-1)/2) = 1 (mod p)]: verifica se 'y'
        //eh residuo quadratico no campo Fp para um primo ímpar 'p'
        //Para C25519 p = 2^(255) - 19, logo (p - 1) = 2^(255) - 20, assim 20 é divisível por 4.
        //Portanto simplificando o teste, temos: y^[(p+1)/4] = 1 (mod p)
        mpz_add_ui(exp_euler, p, 1); //Expoente do Teste de Euler: exp_euler = (p+1)/4
        mpz_cdiv_q_ui(exp_euler, exp_euler, 4);
        //gmp_printf("\nexp euler: %Zd", exp_euler);

        //Testa se P é primo (quanto maior as repeticoes um nao-primo pode ser definido como provavel)
        int primo = mpz_probab_prime_p(p, 50); //Numero de repeticoes para determinar se eh primo
        cout << "\n\n2=primo | 1=provavel | 0=nao-primo: " << primo << endl;
    */

    tamanho_msg = 1; // Numero de vezes necessario para determinar um inteiro y² que passe no Teste de Euler
    for (int j = 0; j < tamanho_msg; j++)
    {
        // y² = x³ + a*x² + x
        // c25519_msg + j = retorna um número y² na c25519 viável?
        mpz_add_ui(x_msg, x_msg, j); // ULTILIZAR A FUNCAO MPZ_NEXTPRIME NO LUGAR????

        // A = x²
        mpz_mul(A, x_msg, x_msg);
        // gmp_printf("\nx²: %Zd", A);

        // B = x³
        mpz_mul(B, A, x_msg);
        // gmp_printf("\nx³: %Zd", B);

        // C = a * x² (onde, a = 486662)
        mpz_mul(C, a, A);
        // gmp_printf("\nx²*a: %Zd", C);

        // y² = x_msg³ + a*x_msg² + x_msg (mod p)
        mpz_add(c25519_msg, B, C);
        mpz_add(c25519_msg, c25519_msg, x_msg);
        // gmp_printf("\n\ny² Sem MOD: %Zd", c25519_msg);
        mpz_mod(c25519_msg, c25519_msg, p); // se resultar no mesmo número o resto eh o msm valor?
        // gmp_printf("\ny² Com MOD: %Zd", c25519_msg); //o numerador não pode ser menos, como 'p' eh enorme, o resultado eh o mesmo valor
/*
        //Calcula Teste de Euler = y^[(p+1)/4] (mod p)
        //mpz_powm_sec(teste_euler, c25519_msg, exp_euler, p); //mpz_powm_SEC eh ultilizado em criptografia pela segurança, pode levar mais tempo
        gmp_printf("\n\nTeste Euler: %Zd", teste_euler);
        mpz_sqrt(teste_euler, teste_euler);
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
    }  cerr << "\nCodificacao da mensagem falhou!" << endl;
    //mpz_set_ui(x_msg, 0);
    //mpz_set_ui(y_msg, 0);
*/}

mpz_sqrt(y_msg, c25519_msg); // Raiz quadrada de 'y²' para 'y'
gmp_printf("\ny_msg: %Zd", y_msg);

std::cout << "\n\n____________________________FIM MSG PARA PONTO____________________________\n" << endl;

// Libera memoria alocada
mpz_clears(x_msg, y_msg, c25519_msg, A, B, C, NULL);

return P_msg;
//return {x_msg, y_msg}; // TRANSFORMAR EM PONTO E RETORNAR
}

/*NAO TESTADO
//2. Montgomery Ladder
FAZ-SE NECESSÁRIO NA MULTIPLICACAO ESCALAR OU
PODE CALCULAR PELAS FÓRMULAS SIMPLIFICADAS DA DE EDWARDS Ed25519 (mais performace)
*/

// 3. Calcula o 'ADD' retornado P3(X3,Y3) somente se Y1 != +/- Y2
// P + Q = Pm + Pn = Pm+n(Xm+n : Zm+n)
/*
// Point addition specific to Curve25519
Point addPoint(const Point& P1, const Point& P2, const mpz_t& prime) {
    Point P3;
    initPoint(P3);

    mpz_t A, B, C, D, E, F, P1_minus_P2_X;
    mpz_inits(A, B, C, D, E, F, P1_minus_P2_X, NULL);

    // Calculate P1_minus_P2.X = X1 - X2
    mpz_sub(P1_minus_P2_X, P1.X, P2.X);
    mpz_mod(P1_minus_P2_X, P1_minus_P2_X, prime);

    // A = (X1 - Z1)*(X2 + Z2)
    mpz_sub(A, P1.X, P1.Z);
    mpz_add(B, P2.X, P2.Z);
    mpz_mul(A, A, B);
    mpz_mod(A, A, prime);

    // B = (X1 + Z1)*(X2 - Z2)
    mpz_add(C, P1.X, P1.Z);
    mpz_sub(D, P2.X, P2.Z);
    mpz_mul(B, C, D);
    mpz_mod(B, B, prime);

    // E = A + B
    mpz_add(E, A, B);
    mpz_mod(E, E, prime);

    // F = A - B
    mpz_sub(F, A, B);
    mpz_mod(F, F, prime);

    // X3 = E^2
    mpz_mul(P3.X, E, E);
    mpz_mod(P3.X, P3.X, prime);

    // Z3 = F^2 * (X1 - X2)
    mpz_mul(P3.Z, F, F);
    mpz_mul(P3.Z, P3.Z, P1_minus_P2_X);
    mpz_mod(P3.Z, P3.Z, prime);

    // Clean up
    mpz_clears(A, B, C, D, E, F, P1_minus_P2_X, NULL);

    return P3;
}
*/
Ponto add_ponto(Ponto P_1, Ponto P_2){
    std::cout << "\n____________________________ADD PONTO________________________________\n" << std::endl; // REMOVER

    gmp_printf("\nP1:(%Zd, %Zd)", P_1.x, P_1.y);
    gmp_printf("\nP2:(%Zd, %Zd)", P_2.x, P_2.y);

    mpz_t P_3x, P_3y;
    mpz_inits(P_3x, P_3y, NULL);

    Ponto P_3;
    initPonto(P_3, P_3x, P_3y); // Inicializa o ponto P_3

    //std::cout << "\n\nContinua? ADD: ";
    //int c = 0;
    //std::cin >> c;

    // A coordenada Y1 != +/- Y2
    if (mpz_cmpabs(P_1.y, P_2.y) == 0){
        cerr << "\nErro Ponto-ADD (Y1 = +/- Y2)!" << endl;
        mpz_set_ui(P_3.x, 0);
        mpz_set_ui(P_3.y, 0);
        return P_3;
        //return {P_3x, P_3y};
    }

    //Se P_2(0, 0), retorne P_1
    else if((mpz_cmp_ui(P_2.x, 0) == 0 && mpz_cmp_ui(P_2.y, 0) == 0)){
        mpz_set(P_3.x, P_1.x);
        mpz_set(P_3.y, P_1.y);

        gmp_printf("\n\nP2(0, 0), logo\nP3:(%Zd, %Zd)", P_3.x, P_3.y);
        return P_3;
        //return {P_3x, P_3y};
    }

    //Se P_1(0, 0), retorne P_2
    else if((mpz_cmp_ui(P_1.x, 0) == 0 && mpz_cmp_ui(P_1.y, 0) == 0)){
        
        mpz_set(P_3.x, P_2.x);
        mpz_set(P_3.y, P_2.y);

        gmp_printf("\n\nP1(0, 0), logo\nP3:(%Zd, %Zd)", P_3.x, P_3.y);
        return P_3;
        //return {P_3x, P_3y};
    }
    
    /*_________________________________________________________________________________________________
        FORMULAS RETIRADAS DO TEOREMA B2 DO APENDIX B (pag. 228)
        Curve25519: New Diﬃe-Hellman Speed Records
    ___________________________________________________________________________________________________*/
    else{
        mpz_t P1_minus_P2_x, x1_plus_z1, x1_minus_z1, x2_plus_z2, x2_minus_z2, var, var_1, var_2;
        mpz_inits(P1_minus_P2_x, x1_plus_z1, x1_minus_z1, x2_plus_z2, x2_minus_z2, var, var_1, var_2, NULL);


	/* Explicit formulas database: dbl-1987-m3
	 *
	 * source 1987 Montgomery "Speeding the Pollard and elliptic curve
	 *   methods of factorization", page 261, fifth display, plus
	 *   common-subexpression elimination
	 * compute A = X2+Z2
	 * compute B = X2-Z2
	 * compute C = X3+Z3
	 * compute D = X3-Z3
	 * compute DA = D A
	 * compute CB = C B
	 * compute X5 = Z1(DA+CB)^2
	 * compute Z5 = X1(DA-CB)^2
	 */
        //P1_minus_P2_x = x1 - x2   mod p
        mpz_sub(P1_minus_P2_x, P_1.x, P_2.x);
        mpz_mod(P1_minus_P2_x, P1_minus_P2_x, p);

        //(x1 + z1) e (x1 - z1)
        mpz_add(x1_plus_z1, P_1.x, P_1.y);
        mpz_sub(x1_minus_z1, P_1.x, P_1.y);

        //(x2 + z2) e (x2 - z2)
        mpz_add(x2_plus_z2, P_2.x, P_2.y);
        mpz_sub(x2_minus_z2, P_2.x, P_2.y);

        //var_1 = (x1 - z1) * (x2 + z2) mod p
        mpz_mul(var_1, x1_minus_z1, x2_plus_z2);
        mpz_mod(var_1, var_1, p);

        //var_2 = (x1 + z1) * (x2 - z2) mod p
        mpz_mul(var_2, x1_plus_z1, x2_minus_z2);
        mpz_mod(var_2, var_2, p);

        //var = (x1 + z1) * (x2 - z2) + (x1 - z1) * (x2 + z2)  mod P
        mpz_add(var, var_2, var_1);
        mpz_mod(var, var, p);
        
        //var_2 = (x1 + z1) * (x2 - z2) - (x1 - z1) * (x2 + z2)  mod p
        mpz_sub(var_2, var_2, var_1);
        mpz_mod(var_2, var_2, p);
        
        //P_3x = z0 * ((x1 + z1) * (x2 - z2) + (x1 - z1) * (x2 + z2))^2  mod p
        mpz_powm_ui(P_3x, var, 2, p);
        mpz_mul(P_3x, P_3x, P_0y);
        mpz_mod(P_3.x, P_3x, p);

        //P_3y = x0 * ((x1 + z1) * (x2 - z2) - (x1 - z1) * (x2 + z2))^2  mod p
        mpz_powm_ui(P_3y, var_2, 2, p);
        //mpz_mul(P_3y, P_3y, P1_minus_P2_x);
        mpz_mul(P_3y, P_3y, P_0x);
        mpz_mod(P_3.y, P_3y, p);
        
        
        /*
        // P_3x = z0 * ((x1 - z1) * (x2 + z2) + (x1 + z1) * (x2 - z2))^2
        mpz_mul(P_3x, var, P_0y);

        // P_3y = x0 * ((x1 - z1) * (x2 + z2) - (x1 + z1) * (x2 - z2))^2
        mpz_mul(P_3y, var_2, P_0x);
*/

        // Limpa as variáveis temporárias
        mpz_clears(x1_plus_z1, x1_minus_z1, x2_plus_z2, x2_minus_z2, var, var_1, var_2, NULL);

        gmp_printf("\nP3:(%Zd, %Zd)", P_3.x, P_3.y);

        std::cout << "\n__________________________FIM ADD PONTO______________________________\n" << endl; // REMOVER

        return P_3;
        //return {P_3x, P_3y};
    }
}

// 4. Calcula o 'DOUBLE' retornado P3(X3,Y3) somente se Y1 != 0
// Quando m = n, 2*Pn = P_(2n)(X_(2n) : Z_(2n))
Ponto double_ponto(Ponto P){
    mpz_t x_plus_z_2, x_minus_z_2, var;
    mpz_inits(x_plus_z_2, x_minus_z_2, var, NULL);

    Ponto P_double;
    initPonto(P_double, P.x, P.y); // Inicializa o ponto P_double

    // Verifica se X ou Y != 0
    if(mpz_cmp_ui(P.x, 0) == 0 || mpz_cmp_ui(P.y, 0) == 0){
        cerr << "\nErro Ponto-Double (X ou Y = 0)!" << endl;
        mpz_set_ui(P_double.x, 0);
        mpz_set_ui(P_double.y, 0);

        // Limpa as variáveis temporárias
        mpz_clears(x_plus_z_2, x_minus_z_2, var, NULL);

        return P_double;
    }

    // Verifica se o ponto P < p (primo)
    else if(mpz_cmp(P.x, p) > 0 || mpz_cmp(P.y, p) > 0){
        cerr << "\nErro Ponto-Double (P > p)!" << endl;
        mpz_set_ui(P_double.x, 0);
        mpz_set_ui(P_double.y, 0);

        // Limpa as variáveis temporárias
        mpz_clears(x_plus_z_2, x_minus_z_2, var, NULL);

        return P_double;
    }

    else{

        /* Explicit formulas database: dbl-1987-m
	    *
	    * source 1987 Montgomery "Speeding the Pollard and elliptic
	    *   curve methods of factorization", page 261, fourth display
	    * X3 = (X1 + Z1)^2 * (X1 - Z1)^2
        * 
        * 4*X1*Z1 = (X1 + Z1)^2 - (X1 - Z1)^2
        * 
	    * Z3 = (4*X1*Z1)*((X1 - Z1)^2 + ((a + 2)/4)*(4*X1*Z1))
	    */
        //(X1 + Z1)^2 
        mpz_add(x_plus_z_2, P.x, P.y);
        mpz_powm_ui(x_plus_z_2, P.x, 2, p);

        //(X1 - Z1)^2
        mpz_sub(x_minus_z_2, P.x, P.y);
        mpz_powm_ui(x_minus_z_2, P.y, 2, p);

        //P_double.x: X3 = (X1 + Z1)^2 * (X1 - Z1)^2 mod p
        mpz_mul(P_double.x, x_plus_z_2, x_minus_z_2);
        mpz_mod(P_double.x, P_double.x, p);

        //var: 4*X1*Z1 = (X1 + Z1)^2 - (X1 - Z1)^2
        mpz_sub(var, x_plus_z_2, x_minus_z_2);

        //P_double.y: Z3 = (4*X1*Z1)*((X1 - Z1)^2 + ((a + 2)/4)*(4*X1*Z1)) mod p
        mpz_mul(P_double.y, a24, var); //a24 = (a + 2)/4 = 121666
        mpz_add(P_double.y, x_minus_z_2, P_double.y);
        mpz_mul(P_double.y, var, P_double.y); 
        mpz_mod(P_double.y, P_double.y, p);

        /*_________________________________________________________________________________________________
        FORMULAS RETIRADAS DO TEOREMA B1 DO APENDIX B (pag. 227)
        Curve25519: New Diﬃe-Hellman Speed Records
        ___________________________________________________________________________________________________

        // x^2 e z^2
        mpz_pow_ui(x_squared, P.x, 2);
        mpz_pow_ui(z_squared, P.y, 2);

        // Qx = (x^2 - z^2)^2
        mpz_sub(var, x_squared, z_squared);
        mpz_pow_ui(double_Px, var, 2);

        // Qy = 4xz(x^2 + axz + z^2)
        mpz_mul_ui(var, P.x, 486662);  // ax = 486662*x
        mpz_mul(axz, var, P.y);        // axz
        mpz_add(var, x_squared, axz);  // x^2 + axz
        mpz_add(var, var, z_squared);  // x^2 + axz + z^2
        mpz_mul(var, var, P.x);        // x(x^2 + axz + z^2)
        mpz_mul(var, var, P.y);        // xz(x^2 + axz + z^2)
        mpz_mul_ui(double_Py, var, 4); // 4xz(x^2 + axz + z^2)
*/
        // Limpa as variáveis temporárias
        mpz_clears(x_plus_z_2, x_minus_z_2, var, NULL);

        return P_double;
    }
}
/*
Ponto scalar_multiplication(const Ponto& P, const mpz_t& k) {
    Ponto Q, tempP;
    initPonto(Q);
    initPonto(tempP);
    mpz_set(tempP.x, P.x);
    mpz_set(tempP.y, P.y);

    bool found = false;
    for (int i = mpz_sizeinbase(k, 2) - 1; i >= 0; i--) {
        if (found) {
            tempP = double_ponto(tempP); // Double the point
        }
        if (mpz_tstbit(k, i)) {
            if (!found) {
                mpz_set(Q.x, tempP.x);
                mpz_set(Q.y, tempP.y);
                found = true;
            } else {
                Q = add_ponto(Q, tempP); // Add to the result
            }
        }
    }

    if (!found) {
        std::cerr << "Scalar is zero, returning point at infinity" << std::endl;
        // Handle the case for scalar 0, usually returning the point at infinity or an identity element
    }

    clearPonto(tempP); // Clear temporary point
    return Q; // Return the result of scalar multiplication
}*/

// 5. Multiplicacao escalar chama 'ADD' com a condição de k existir (k shift até encerrar os bits)
// P1 sempre sera calculado pelo 'DOUBLE'
Ponto multiplicacao_escalar(mpz_t k_rand, Ponto Ponto_curva){
    std::cout << "\n\n__________________________Mult Escalar______________________________\n" << endl; // REMOVER

    mpz_set_ui(k_rand, 2); //teste controlado 0100

    gmp_printf("\nk: %Zd", k_rand);

    Ponto Ponto_R, Ponto_B;
    initPonto(Ponto_R); //Inicializa o ponto Ponto_resultante
    initPonto(Ponto_B, Ponto_curva.x, Ponto_curva.y); //Inicializa o ponto Ponto_curva

    gmp_printf("\nPonto Curva: (%Zd, %Zd)", Ponto_B.x, Ponto_B.y);

    // Verifica se k é 0
    if(mpz_cmp_ui(k_rand, 0) == 0){
        gmp_printf("\nk = 0\nx: % Zd", Ponto_B.x); // Apenas x eh necessario para a chave publica

        clearPonto(Ponto_R); // Limpa o ponto Ponto_R

        return Ponto_B; // Retorna o Ponto Curva se k é 0
    }

    else{   
        bool found = false;
        size_t num_bits = mpz_sizeinbase(k_rand, 2); // Número de bits de k
        std::cout << "\nNumero de bits de k: " << num_bits << std::endl;

        // Loop over each bit of the scalar
        for(size_t i = 0; i < num_bits; ++i){

            std::cout << "\nBit atual: " << mpz_tstbit(k_rand, i) << " na posição: " << i << std::endl; // Imprime o bit e sua posição
            
            if(found){
                std::cout << "\n\n__________________________DOUBLE______________________________\n" << endl; // REMOVER

                Ponto_B = double_ponto(Ponto_B); 
                gmp_printf("\nPonto B: (%Zd, %Zd)", Ponto_B.x, Ponto_B.y);

                std::cout << "\n__________________________FIM DOUBLE______________________________\n" << endl; // REMOVER
            }
            
            if(mpz_tstbit(k_rand, num_bits - 1 - i)){//Se o bit é 1 (bit menos significativo)
                if(!found){
                    mpz_set(Ponto_R.x, Ponto_B.x);
                    mpz_set(Ponto_R.y, Ponto_B.y);
                    gmp_printf("\nPonto R: (%Zd, %Zd)", Ponto_R.x, Ponto_R.y);
                    found = true;
                } else{
                    Ponto_R = add_ponto(Ponto_R, Ponto_B);
                }
                
                //std::cout << "\n\nContinua? K: ";
                //int c = 0;
                //std::cin >> c;
            }
        }
        gmp_printf("\nMultiplicacao Escalar\nx: %Zd \ny: %Zd", Ponto_R.x, Ponto_R.y); 

        std::cout << "\n________________________FIM Mult Escalar____________________________\n" << endl; // REMOVER
        
        clearPonto(Ponto_B); // Limpa o ponto Ponto_B
        
        return Ponto_R; // Retorna o resultado da multiplicação escalar
    }
}

// 6. Gerar um numero inteiro randomico no intervalo [1, n-1] e retorna uma CHAVE PRIVADA (k)
void gera_int_rand(mpz_t k){

    //________________________INICIO GERAR SEMENTE________________________

    // Gera a semente sem bloqueio, diferente do /dev/random que pode bloquear se nao houver entropia suficiente
    // urandom eh seguro o suficiente, mas para criptografia eh garantido ultilizar random (porém pode haver bloqueio e demorar)
    ifstream urandom("/dev/urandom", ios::binary);
    if (!urandom)
    {
        cerr << "Erro ao abrir /dev/urandom" << endl;
        return;
    }
    unsigned char seed[64]; // 64 bytes de semente para C25519 (pode ser menor e seguro)

    /*"64-bits of information to avoid repeating the same seed...
    ...If you read 4 bytes from this device then you will get a nicely random and unpredictable 32-bit seed
    value, and you can read as many bytes as you need."
    (Good Practice in (Pseudo) Random Number Generation for Bioinformatics Applications
    David Jones, UCL Bioinformatics Group, 2010)*/
    urandom.read(reinterpret_cast<char *>(&seed), sizeof(seed)); // armazena em seed como char
    urandom.close();

    std::cout << "\n\n____________________________RANDOMICA________________________________\n" << endl;

    std::cout << "Seed: ";
    for (int i = 0; i < sizeof(seed); ++i)
    {
        std::cout << hex << static_cast<int>(seed[i]);
    }
    std::cout << dec << endl;

    // Semente gerada em um inteiro
    std::cout << "\nTamanho da Seed: " << sizeof(seed) << endl;

    // Converte a semente char em mpz_t
    mpz_t conv_seed;
    mpz_init(conv_seed);
    mpz_import(conv_seed, sizeof(seed), 1, 1, 0, 0, seed); // convertendo char para mpz_t
    gmp_printf("\nSemente convertida: %Zd ", conv_seed);

    //________________________FIM GERAR SEMENTE________________________

    //________________________INICIO GERAR STATE PELA SEMENTE________________________
    // Inicializar o gmp-state com default = mt (Mersenne Twister algorithm)
    gmp_randstate_t state;
    gmp_randinit_default(state); // necessita inicializar para ultilizar as demais funcoes (por defalut eh mt)

    // Inicia o gerador de estado da GMP para ultilizar mpz_urandom com a semente fornecida
    gmp_randseed(state, conv_seed); // state eh um endereco de memoria

    //________________________FIM GERAR STATE PELA SEMENTE________________________

    // Zera a chave privada
    mpz_init_set_ui(k, 0);

    // Gera uma chave privada baseada no STATE com SEED e no intervalo [1, n-1]
    do
    {
        mpz_urandomm(k, state, n);
    } while (mpz_cmp_ui(k, 1) <= 0); // Enquanto k <= 1

    gmp_printf("\n\nEscalar randomico (k): % Zd ", k);

    // Limpa as memorias
    mpz_clear(conv_seed);
    gmp_randclear(state);

    std::cout << "\n\n___________________________FIM RANDOMICA____________________________\n" << endl;
}

// 7. Gera a CHAVE PUBLICA ultilizando a multiplicacao escalar da CHAVE PRIVADA com o Ponto base dado P1(x1,y1)
// Retorna P2(X2, Y2)???????????????
Ponto gera_chave_pbl(mpz_t chave_prv, Ponto P0){
    return multiplicacao_escalar(chave_prv, P0);
}


//8. Encripta a mensagem ultilizando a CHAVE PUBLICA
void encriptar_mensagem(Ponto msg_cod, Ponto chave_pbl, Ponto& C1, Ponto& C2){
    std::cout << "\n\n____________________________ENCRYPT________________________________\n" << std::endl; // REMOVER
    mpz_t chv_prv_efemera;
    mpz_init(chv_prv_efemera);

    gera_int_rand(chv_prv_efemera); // Gera uma chave privada efemera
    /*
    Ponto C1, C2, k_mult_chv_pbl;
    initPonto(C1);
    initPonto(C2);
    initPonto(k_mult_chv_pbl);
    */

    Ponto k_mult_chv_pbl;
    initPonto(C1);
    initPonto(C2);
    initPonto(k_mult_chv_pbl);

    C1 = multiplicacao_escalar(chv_prv_efemera, P_0); //C1 = k*P_0
    k_mult_chv_pbl = multiplicacao_escalar(chv_prv_efemera, chave_pbl); // k*Pb
    C2 = add_ponto(msg_cod, k_mult_chv_pbl); //C2 = Pm + k*Pb

    mpz_clear(chv_prv_efemera);
    std::cout << "\n\n________________________FIM ENCRYPT________________________________\n" << std::endl; // REMOVER
}


//9. Decripta a mensagem ultilizando a CHAVE PRIVADA
Ponto decriptar_mensagem(Ponto C1, Ponto C2, mpz_t chave_prv){
    std::cout << "\n\n____________________________DECRYPT________________________________\n" << std::endl; // REMOVER

    Ponto P_msg, chv_prv_mult_C1;
    initPonto(P_msg);
    initPonto(chv_prv_mult_C1);

    chv_prv_mult_C1 = multiplicacao_escalar(chave_prv, C1); //k*C1

    mpz_neg(chv_prv_mult_C1.y, chv_prv_mult_C1.y);//k*C1 = (x, -y) 

    P_msg = add_ponto(C2, chv_prv_mult_C1); //P_msg = C2 + k*C1

    std::cout << "\n___________________________FIM DECRYPT____________________________\n" << std::endl; // REMOVER
    return P_msg;
}

int main()
{
    //!!!!!!!!!!!!!!!!!!!!!!!!!TESTAR CUSTO COMPUTACIONAL VS PRECISÃO!!!!!!!!!!!!!!!!!!!!!!!!!!!

    /*_______________________________________________________________________
        Inicializa os parametros para C25519 de 128-bit de segurança
    _________________________________________________________________________

    Melhor iniciar na main() e passa via funcoes pois necessita inicializar e limpar a memoria sempre
    Cofator 8 ("has order h⋅n, where h=8 and where n is a prime number")
    */

    // Numero primo fixo p = (2^255) - 19 = 5,789604462×10⁷⁶
    // p=0x7fffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffed
    mpz_init(p);
    mpz_ui_pow_ui(p, 2, 255);
    mpz_sub_ui(p, p, 19);

    // Inteiro que A² - 4 nao eh raiz do modulo 'p' (A = 486662 ou 0x76d06)
    //"A2 792 −4 is not a square in GF(p), whereas A+2 is"
    mpz_init_set_ui(a, 486662);
    mpz_init_set_ui(a24, 121666); //a24 = (a + 2)/4 = 121666

    // B = 1 ou 0x01, assim nao se faz necessario inicializar a memoria (Montgomery Curve -> By² = x³ + Ax² + x)
    // mpz_init_set_ui(b, 1);

    // Ordem da curva eliptica ou Fp² (n)
    // n = 2^(252) + 27742317777372353535851937790883648493
    // n: 7237005577332262213973186563042994240857116359379907606001950938285454250989 (=2^252 + 0x14def9de a2f79cd6 5812631a 5cf5d3ed)
    // CONFERIR 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    mpz_t n_var;
    mpz_init(n);
    // mpz_set_str(n, "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED", 16);
    mpz_init_set_str(n_var, "27742317777372353535851937790883648493", 10);
    mpz_ui_pow_ui(n, 2, 252);
    mpz_add(n, n, n_var); // CONFERIR SE MULTIPLICOU O COFATOR 8!!!!!!!!!!!!!!!!!!

    // Ponto base definido por Daniel J. Bernstein Gu = 9 (=0x9)

    // Sugestao para coordenada base y1
    // Gv = 43114425171068552920764898935933967039\370386198203806730763910166200978582548
    //(=0x5f51e65e 475f794b 1fe122d3 88b72eb3 6dc2b281 92839e4d d6163a5d 81312c14)
    // CONFERIR 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    //mpz_init_set_str(P_0y, "14781619447589544791020593568409986887264606134616475288964881837755586237401", 10);
    // 57896044618658097711785492504343953926634992332820282019728792003956564819949
    mpz_init_set_ui(P_0x, 2); //teste controlado 
    mpz_init_set_ui(P_0y, 3);
   
    initPonto(P_0, P_0x, P_0y); //Inicializa o ponto P_0

    // As funcoes ADD e DOUBLE para Curva25519 que eh uma Montgomery Curve (1987) com um numero primo fixo (p)
    // Um ponto racional P(x, y) eh representado em coordeenadas Montgomery P(X : Z), sendo x = X/Z para Z != 0
    // Assim, para pontos racionais temos: Pm(Xm : Zm) = [m]P(X : Z) e Pn(Xn : Zn) = [n]P(X : Z)

    // Inicia como zero o inteiro que receberah a mensagem para codificacao e a chave privada
    mpz_t msg_t_gmp, msg_des;
    mpz_inits(msg_t_gmp, msg_des, NULL);

    // Semente para gerar numero randomico da Chave Privada
    // mpz_t chave_prv, seed;
    // mpz_inits(chave_prv, seed, nullptr);
    mpz_t chv_prv, chv_prv_ef, k;
    mpz_inits(chv_prv, chv_prv_ef, k, NULL);

    /*********************************************************************/

    // Valores iniciados da Curva25519
    std::cout << "\n____________________________PARAMETROS CURVA 25519____________________________" << endl;
    gmp_printf("\nP  = % Zd ", p);
    gmp_printf("\nA  = % Zd ", a);
    // gmp_printf ("\nB = % Zd ", b);
    gmp_printf("\nN  = % Zd ", n);
    gmp_printf("\nX1 = % Zd ", P_0x);
    gmp_printf("\nY1 = % Zd ", P_0y);
    std::cout << "\n______________________________________________________________________________" << endl;

    string mensagem;
    std::cout << "\nDigite a mensagem para codificacao ECC-25519: ";
    std::cin >> mensagem;

    // Converte a mensagem para inteiro GMP
    string_to_mpz(mensagem, msg_t_gmp);
    gmp_printf("\nMensagem em inteiro (GMP): %Zd \n", msg_t_gmp);

    // Codifica a mensagem (inteiro) inserida para um ponto na curva eliptica C25519
    Ponto msg_cod = codifica_mensagem_para_ponto_da_c25519(msg_t_gmp);
    gmp_printf("\nMensagem Codificada\nx: % Zd", msg_cod.x);
    gmp_printf("\ny: % Zd", msg_cod.y);

    // Gera a Chave Privada (k) limitada pela ordem da curva eliptica (n), retornando inteiro
    gera_int_rand(k);
    mpz_set(chv_prv, k);
    gmp_printf("\nChave Privada: % Zd ", chv_prv);

    // Gera a Chave Publica fornecendo a Chave Privada
    // pela multiplicacao escalar ultilizando o ponto inicial (x1, y1)
    Ponto chave_pbl = gera_chave_pbl(chv_prv, P_0);
    //Ponto chave_pbl = gera_chave_pbl(chv_prv, {P_0x, P_0y});
    gmp_printf("\n\nChave Publica \nx: % Zd", chave_pbl.x);
    gmp_printf("\ny: % Zd", chave_pbl.y);

    Ponto C1, C2;
    initPonto(C1);
    initPonto(C2);  

    encriptar_mensagem(msg_cod, chave_pbl, C1, C2); //RETORNA UM VETOR DE PONTO??????
    gmp_printf("\nMensagem criptografada\nC1: x = % Zd | y = % Zd", C1.x, C1.y);
    gmp_printf("\nC2: x = % Zd | y = % Zd", C2.x, C2.y);

    Ponto msg_dec;
    initPonto(msg_dec);

    msg_dec = decriptar_mensagem(C1, C2, chv_prv);
    gmp_printf("\nMensagem descriptografada: % Zd", msg_dec.x);

    // Limpa variáveis para liberar memória
    // mpz_clears(h, b, NULL);
    mpz_clears(p, a, n, P_0x, P_0y, msg_t_gmp, chv_prv, chv_prv_ef, NULL);
    std::cout << endl << endl;

    return 0;
}