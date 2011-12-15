/*
 *    No matter where you got this code from, be aware that MIRACL is NOT 
 *    free software. For commercial use a license is required.
 *	  See www.shamus.ie
 *
 * mnt_pair.cpp
 *
 * MNT curve, ate pairing embedding degree 6, ideal for security level AES-80
 *
 * 
 *  Irreducible binomial MUST be of the form x^6+2. This excludes many of the curves
 *  found using the mnt utility!
 *  NOTE: This version uses a "compositum". That is the ZZn6 class is a cubic tower over ZZn2, but can
 *  also be considered as a quadratic tower over ZZn3. The routine shuffle converts from one form to the other.
 *  The former is fastest for ZZn6 arithmetic, the latter form is required for handling the second parameter
 *  to the pairing, which is on the quadratic twist E(Fp3)
 *
 * Provides high level interface to pairing functions
 * 
 * GT=pairing(G2,G1)
 *
 * This is calculated on a Pairing Friendly Curve (PFC), which must first be defined.
 *
 * G1 is a point over the base field, and G2 is a point over an extension field of degree 3
 * GT is a finite field point over the 6-th extension, where 6 is the embedding degree.
 *
 */

#define MR_PAIRING_MNT
#include "pairing_3.h"

// AES_SECURITY=80 bit curve
// MNT curve parameters, x,A,B
// Thanks to Drew Sutherland for providing the MNT curve
// irreducible poly is x^6+2
static char param[]="-D285DA0CFEF02F06F812";
static char curveB[]="77479D33943B5B1F590B54258B72F316B3261D45";

void read_only_error(void)
{
	cout << "Attempt to write to read-only object" << endl; 
	exit(0);
}

void set_frobenius_constant(ZZn2 &X)
{
    Big p=get_modulus();
    switch (get_mip()->pmod8)
    {
    case 5:
         X.set((Big)0,(Big)1); // = (sqrt(-2)^(p-1)/2     
         break;
    case 3:                     // = (1+sqrt(-1))^(p-1)/2                                
         X.set((Big)1,(Big)1);      
         break;
   case 7: 
         X.set((Big)2,(Big)1); // = (2+sqrt(-1))^(p-1)/2
    default: break;
    }
    X=pow(X,(p-1)/3);
}

// Using SHA as basic hash algorithm
//
// Hash function
// 

#define HASH_LEN 20

Big H1(char *string)
{ // Hash a zero-terminated string to a number < modulus
    Big h,p;
    char s[HASH_LEN];
    int i,j; 
    sha sh;

    shs_init(&sh);

    for (i=0;;i++)
    {
        if (string[i]==0) break;
        shs_process(&sh,string[i]);
    }
    shs_hash(&sh,s);
    p=get_modulus();
    h=1; j=0; i=1;
    forever
    {
        h*=256; 
        if (j==HASH_LEN)  {h+=i++; j=0;}
        else         h+=s[j++];
        if (h>=p) break;
    }
    h%=p;
    return h;
}

void PFC::start_hash(void)
{
	shs_init(&SH);
}

Big PFC::finish_hash_to_group(void)
{
	Big hash;
	char s[HASH_LEN];
    shs_hash(&SH,s);
    hash=from_binary(HASH_LEN,s);
	return hash%(*ord);
}

void PFC::add_to_hash(const GT& x)
{
	ZZn6 u=x.g;
	ZZn2 v;
	ZZn l,h;
	Big a,xx[2];
	int i,j,m;

	u.get(v);
	v.get(l,h);
	xx[0]=l; xx[1]=h;

    for (i=0;i<2;i++)
    {
        a=xx[i];
        while (a>0)
        {
            m=a%256;
            shs_process(&SH,m);
            a/=256;
        }
    }

}

void PFC::add_to_hash(const G2& x)
{
	ZZn3 X,Y;
	ECn3 v=x.g;
	Big a;
	ZZn xx[6];

	int i,m;

	v.get(X,Y);
	X.get(xx[0],xx[1],xx[2]);
	Y.get(xx[3],xx[4],xx[5]);
	for (i=0;i<6;i++)
    {
        a=(Big)xx[i];
        while (a>0)
        {
            m=a%256;
            shs_process(&SH,m);
            a/=256;
        }
    }
}

void PFC::add_to_hash(const G1& x)
{
	Big a,X,Y;
	int i,m;
	x.g.get(X,Y);
	a=X;
    while (a>0)
    {
        m=a%256;
        shs_process(&SH,m);
        a/=256;
    }
	a=Y;
    while (a>0)
    {
        m=a%256;
        shs_process(&SH,m);
        a/=256;
    }
}

void PFC::add_to_hash(const Big& x)
{
	int m;
	Big a=x;
    while (a>0)
    {
        m=a%256;
        shs_process(&SH,m);
        a/=256;
    }
}

Big H2(ZZn6 y)
{ // Hash and compress an Fp6 to a big number
    sha sh;
    ZZn u,v,w;
	ZZn2 x;
    Big a,h,xx[2];
    char s[HASH_LEN];
    int i,j,m;

    shs_init(&sh);
	y.get(x);
    x.get(u,v);
    xx[0]=u; xx[1]=v;
   
    for (i=0;i<2;i++)
    {
        a=xx[i];
        while (a>0)
        {
            m=a%256;
            shs_process(&sh,m);
            a/=256;
        }
    }
    shs_hash(&sh,s);
    h=from_binary(HASH_LEN,s);
    return h;
}

void extract(ECn& A,ZZn& x,ZZn& y)
{ 
    x=(A.get_point())->X;
    y=(A.get_point())->Y;
}

void extract(ECn& A,ZZn& x,ZZn& y,ZZn& z)
{ 
    big t;
    x=(A.get_point())->X;
    y=(A.get_point())->Y;
    t=(A.get_point())->Z;
    if (A.get_status()!=MR_EPOINT_GENERAL) z=1;
    else                                   z=t;
}

ZZn6 shuffle(const ZZn3 &first, const ZZn3 &second)
{ // shuffle from a pair ZZn3's to three ZZn2's, as required by ZZn6
	ZZn6 w;
	ZZn x0,x1,x2,x3,x4,x5;
	ZZn2 t0,t1,t2;
	first.get(x0,x2,x4);
	second.get(x1,x3,x5);
	t0.set(x0,x3);
	t1.set(x1,x4);
	t2.set(x2,x5);
	w.set(t0,t1,t2);
	return w;
}

void unshuffle(ZZn6 &S,ZZn3 &first,ZZn3 &second)
{ // unshuffle a ZZn6 into two ZZn3's 
	ZZn x0,x1,x2,x3,x4,x5;
	ZZn2 t0,t1,t2;
	S.get(t0,t1,t2);
	t0.get(x0,x3);
	t1.get(x1,x4);
	t2.get(x2,x5);
	first.set(x0,x2,x4);
	second.set(x1,x3,x5);
}

// Calculate q*P. P(X,Y) -> P(X^p,Y^p))

void q_power_frobenius(ECn3 &S,ZZn2& X)
{
	ZZn6 X1,X2,Y1,Y2;
	ZZn3 Sx,Sy,T;

	int qnr=get_mip()->cnr;

	S.get(Sx,Sy);

	// untwist    
    Sx=Sx/qnr;
    Sy=tx(Sy);
    Sy=Sy/(qnr*qnr);

	X1=shuffle(Sx,(ZZn3)0); Y1=shuffle((ZZn3)0,Sy);
	X1.powq(X); Y1.powq(X);
	unshuffle(X1,Sx,T); unshuffle(Y1,T,Sy);
	
	// twist
	Sx=qnr*Sx;
	Sy=txd(Sy*qnr*qnr);
	S.set(Sx,Sy);
}

//
// Line from A to destination C. Let A=(x,y)
// Line Y-slope.X-c=0, through A, so intercept c=y-slope.x
// Line Y-slope.X-y+slope.x = (Y-y)-slope.(X-x) = 0
// Now evaluate at Q -> return (Qy-y)-slope.(Qx-x)
//

ZZn6 line(ECn3& A,ECn3& C,ECn3& B,int type,ZZn3& slope,ZZn& Px,ZZn& Py)
{
    ZZn6 w;
	ZZn3 d;

    ZZn3 x,y;
    A.get(x,y);
    d.set1(Py);
	w=shuffle(y-slope*(Px+x),d);

    return w;
}

//
// Add A=A+B  (or A=A+A) 
// Return line function value
//

ZZn6 g(ECn3& A,ECn3& B,ZZn& Px,ZZn& Py)
{
    BOOL type;
    ZZn3 lam,ex1,ex2;
    ECn3 Q=A;

// Evaluate line from A to A+B
    type=A.add(B,lam);

    return line(Q,A,B,type,lam,Px,Py);
}

// if multiples of G2 can be precalculated, its a lot faster!

ZZn6 gp(ZZn3* ptable,int &j,ZZn& Px,ZZn& Py)
{
	ZZn6 w;
	ZZn3 d;
	d.set1(Py);
	w=shuffle(ptable[j]*Px+ptable[j+1],d);
	j+=2;
	return w;
}

//
// Spill precomputation on pairing to byte array
//

int PFC::spill(G2& w,char *& bytes)
{
	int i,j,len,m;
	int bytes_per_big=(MIRACL/8)*(get_mip()->nib-1);
	
	ZZn a,b,c;
	Big X=*x;
	if (w.ptable==NULL) return 0;

	m=2*(bits(X)-2+ham(X));
	len=m*3*bytes_per_big;

	bytes=new char[len];
	for (i=j=0;i<m;i++)
	{
		w.ptable[i].get(a,b,c);
		to_binary((Big)a,bytes_per_big,&bytes[j],TRUE);
		j+=bytes_per_big;
		to_binary((Big)b,bytes_per_big,&bytes[j],TRUE);
		j+=bytes_per_big;
		to_binary((Big)c,bytes_per_big,&bytes[j],TRUE);
		j+=bytes_per_big;
	}

	delete [] w.ptable; 
	w.ptable=NULL;
	return len;
}

//
// Restore precomputation on pairing to byte array
//

void PFC::restore(char * bytes,G2& w)
{
	int i,j,len,m;
	int bytes_per_big=(MIRACL/8)*(get_mip()->nib-1);
	
	ZZn a,b,c;
	Big X=*x;
	if (w.ptable!=NULL) return;

	m=2*(bits(X)-2+ham(X));
	len=m*3*bytes_per_big;

	w.ptable=new ZZn3[m];
	for (i=j=0;i<m;i++)
	{
		a=from_binary(bytes_per_big,&bytes[j]);
		j+=bytes_per_big;
		b=from_binary(bytes_per_big,&bytes[j]);
		j+=bytes_per_big;
		c=from_binary(bytes_per_big,&bytes[j]);
		j+=bytes_per_big;
		w.ptable[i].set(a,b,c);
	}
	for (i=0;i<len;i++) bytes[i]=0;
	
	delete [] bytes;
}

// precompute G2 table for pairing

int PFC::precomp_for_pairing(G2& w)
{
	int i,j,nb,type,len;
	ECn3 A,Q,B;
	ZZn3 lam,x1,y1;
	Big X=*x;
	
	A=w.g;
	B=A;
	nb=bits(X);
	j=0;
	len=2*(nb-2+ham(X));
	w.ptable=new ZZn3[len];

    for (i=nb-2;i>=0;i--)
    {
		Q=A;
// Evaluate line from A to A+B
		A.add(A,lam);
		Q.get(x1,y1);
		w.ptable[j++]=-lam; w.ptable[j++]=y1-lam*x1; 

		if (bit(X,i)==1)
		{
			Q=A;
			type=A.add(B,lam);
			Q.get(x1,y1);
			w.ptable[j++]=-lam; w.ptable[j++]=y1-lam*x1; 
		}
    }
	return len;
}

GT PFC::multi_miller(int n,G2** QQ,G1** PP)
{
	GT z;
    ZZn *Px,*Py;
	int i,j,*k,nb;
    ECn3 *Q,*A;
	ECn P;
    ZZn6 res;
	Big X=*x;

	Px=new ZZn[n];
	Py=new ZZn[n];
	Q=new ECn3[n];
	A=new ECn3[n];
	k=new int[n];

    nb=bits(X);
	res=1;  

	for (j=0;j<n;j++)
	{
		k[j]=0;
		P=PP[j]->g; normalise(P); Q[j]=QQ[j]->g; 
		extract(P,Px[j],Py[j]);
		Px[j]+=Px[j];
		Py[j]+=Py[j];
	}

	for (j=0;j<n;j++) A[j]=Q[j];

	for (i=nb-2;i>=0;i--)
	{
		res*=res;
		for (j=0;j<n;j++)
		{
			if (QQ[j]->ptable==NULL)
				res*=g(A[j],A[j],Px[j],Py[j]);
			else
				res*=gp(QQ[j]->ptable,k[j],Px[j],Py[j]);
		}
		if (bit(X,i)==1)
			for (j=0;j<n;j++) 
			{
				if (QQ[j]->ptable==NULL)
					res*=g(A[j],Q[j],Px[j],Py[j]);
				else
					res*=gp(QQ[j]->ptable,k[j],Px[j],Py[j]);
			}
		if (res.iszero()) return 0;  
	}

	delete [] k;
	delete [] A;
	delete [] Q;
	delete [] Py;
	delete [] Px;

	z.g=res;
	return z;
}

//
// R-ate Pairing G2 x G1 -> GT
//
// P is a point of order q in G1. Q(x,y) is a point of order q in G2. 
// Note that Q is a point on the sextic twist of the curve over Fp^2, P(x,y) is a point on the 
// curve over the base field Fp
//

GT PFC::miller_loop(const G2& QQ,const G1& PP)
{ 
	GT z;
    int i,j,n,nb,nbw,nzs;
    ECn3 A,Q;
	ECn P;
	ZZn Px,Py;
	BOOL precomp;
    ZZn6 res;
	Big X=*x;

	P=PP.g; Q=QQ.g;
	precomp=FALSE;
	if (QQ.ptable!=NULL) precomp=TRUE;

	normalise(P);
	extract(P,Px,Py);

    Px+=Px;  // because x^6+2 is irreducible.. simplifies line function calculation
    Py+=Py; 

    res=1;  
    A=Q;    // reset A
    nb=bits(X);
	res.mark_as_miller();
	j=0;

    for (i=nb-2;i>=0;i--)
    {
		res*=res;
		if (precomp) res*=gp(QQ.ptable,j,Px,Py);
		else         res*=g(A,A,Px,Py);

		if (bit(X,i)==1)
		{
			if (precomp) res*=gp(QQ.ptable,j,Px,Py);
			else         res*=g(A,Q,Px,Py);
		}
    }

	z.g=res;
	return z;
}

GT PFC::final_exp(const GT& z)
{
	GT y;
	ZZn6 w,res;
	Big X=*x;

	res=z.g;

    w=res;   
    w.powq(*frob);
    res*=w;                        // ^(p+1)

    w=res;
    w.powq(*frob); w.powq(*frob); w.powq(*frob);
    res=w/res;                     // ^(p^3-1)

// exploit the clever "trick" for a half-length exponentiation!

    res.mark_as_unitary();

    w=res;
    res.powq(*frob);  // res*=res;  // res=pow(res,CF);
 
    if (X<0) res/=powu(w,-X);
    else res*=powu(w,X);

    y.g=res;

	return y;
}

PFC::PFC(int s)
{
	int mod_bits,words;
	if (s!=80)
	{
		cout << "No suitable curve available" << endl;
		exit(0);
	}
	mod_bits=2*s;

	if (mod_bits%MIRACL==0)
		words=(mod_bits/MIRACL);
	else
		words=(mod_bits/MIRACL)+1;

#ifdef MR_SIMPLE_BASE
	miracl *mip=mirsys((MIRACL/4)*words,16);
#else
	miracl *mip=mirsys(words,0); 
	mip->IOBASE=16;
#endif

	B=new Big;
	x=new Big;
	mod=new Big;
	ord=new Big;
	cof=new Big;
	npoints=new Big;
	trace=new Big;
	frob=new ZZn2;

	*B=curveB;
	S=s;
	*x=param;
	Big X=*x;

	*mod=X*X+1;
	*npoints=X*X-X+1;
	*trace=X+1;
	*cof=X*X+X+1;
	*ord=*npoints;
	ecurve(-3,*B,*mod,MR_PROJECTIVE);
	set_frobenius_constant(*frob);
	Big sru=pow((ZZn)-2,(*mod-1)/6);   // x^6+2 is irreducible
    set_zzn3(-2,sru);
	mip->TWIST=MR_QUADRATIC;   // twisted curve E'(ZZn3)
}

PFC::~PFC()
{
	delete B;
	delete x;
	delete mod;
	delete ord;
	delete cof;
	delete npoints;
	delete trace;
	delete frob;
	mirexit();
}

G1 PFC::mult(const G1& w,const Big& k)
{
	G1 z;
	if (w.mtable!=NULL)
	{ // we have precomputed values
		Big e=k;
		if (k<0) e=-e;

		int i,j,t=w.mtbits; //MR_ROUNDUP(2*S,WINDOW_SIZE); 
		j=recode(e,t,WINDOW_SIZE,t-1);
		z.g=w.mtable[j];
		for (i=t-2;i>=0;i--)
		{
			j=recode(e,t,WINDOW_SIZE,i);
			z.g+=z.g;
			if (j>0) z.g+=w.mtable[j];
		}
		if (k<0) z.g=-z.g;
	}
	else
	{
		z.g=w.g;
		z.g*=k;
	}
	return z;
}

// GLV + Galbraith-Scott

G2 PFC::mult(const G2& w,const Big& k)
{
	G2 z;
	Big X=*x;
	if (w.mtable!=NULL)
	{ // we have precomputed values
		Big e=k;
		if (k<0) e=-e;

		int i,j,t=w.mtbits; //MR_ROUNDUP(2*S,WINDOW_SIZE); 
		j=recode(e,t,WINDOW_SIZE,t-1);
		z.g=w.mtable[j];
		for (i=t-2;i>=0;i--)
		{
			j=recode(e,t,WINDOW_SIZE,i);
			z.g+=z.g;
			if (j>0) z.g+=w.mtable[j];
		}
		if (k<0) z.g=-z.g;
	}
	else
	{
		ECn3 v=w.g;
		q_power_frobenius(v,*frob);
		z.g=mul(v,k/X,w.g,k%X);
	}
	return z;
}

// GLV method + Galbraith-Scott idea

GT PFC::power(const GT& w,const Big& k)
{
	GT z;
	Big X=*x;
	if (w.etable!=NULL)
	{ // precomputation is available
		Big e=k;
		if (k<0) e=-e;

		int i,j,t=w.etbits; //MR_ROUNDUP(2*S,WINDOW_SIZE); 
		j=recode(e,t,WINDOW_SIZE,t-1);
		z.g=w.etable[j];
		for (i=t-2;i>=0;i--)
		{
			j=recode(e,t,WINDOW_SIZE,i);
			z.g*=z.g;
			if (j>0) z.g*=w.etable[j];
		}
		if (k<0) z.g=inverse(z.g);
	}
	else
	{
		ZZn6 y=w.g;
		y.powq(*frob);
		z.g=powu(y,k/X,w.g,k%X);
	}
	return z;
}

// Use Scott et al. idea - http://eprint.iacr.org/2008/530.pdf
// Map to point of correct order

void map(ECn3 &S,Big x, ZZn2& X)
{ // S=Phi(2xP)+phi^2(2xP)
	ZZn6 X1,X2,Y1,Y2;
	ZZn3 Sx,Sy,T;
	ECn3 S2;
	int qnr=get_mip()->cnr;

	S*=x; S+=S; // hard work done here

	S.get(Sx,Sy);

	// untwist    
    Sx=Sx/qnr;
    Sy=tx(Sy);
    Sy=Sy/(qnr*qnr);

	X1=shuffle(Sx,(ZZn3)0); Y1=shuffle((ZZn3)0,Sy);
	X1.powq(X); Y1.powq(X);
	X2=X1; Y2=Y1;
	X2.powq(X); Y2.powq(X);
	unshuffle(X1,Sx,T); unshuffle(Y1,T,Sy);
	
	// twist
	Sx=qnr*Sx;
	Sy=txd(Sy*qnr*qnr);
	S.set(Sx,Sy);
	unshuffle(X2,Sx,T); unshuffle(Y2,T,Sy);

	//twist (again, like we did last summer...)
	Sx=qnr*Sx;
	Sy=txd(Sy*qnr*qnr);
	S2.set(Sx,Sy);
	S+=S2;
}

// random group element

void PFC::random(Big& w)
{
	w=rand(*ord);
}

// random AES key

void PFC::rankey(Big& k)
{
	k=rand(S,2);
}

void PFC::hash_and_map(G2& w,char *ID)
{
    int i;
    ZZn3 XX;
	Big X=*x;
 
    Big x0=H1(ID);
    forever
    {
        x0+=1;
        XX.set2((ZZn)x0);
        if (!w.g.set(XX)) continue;

        break;
    }
	map(w.g,X,*frob);
}

void PFC::random(G2& w)
{
    int i;
    ZZn3 XX;
	Big X=*x;
 
    Big x0=rand(*mod);
    forever
    {
        x0+=1;
        XX.set2((ZZn)x0);
        if (!w.g.set(XX)) continue;

        break;
    }
	map(w.g,X,*frob);
}

void PFC::hash_and_map(G1& w,char *ID)
{
    Big x0=H1(ID);
    while (!w.g.set(x0,x0)) x0+=1;
}

void PFC::random(G1& w)
{
	Big x0=rand(*mod);

	while (!w.g.set(x0,x0)) x0+=1;
}

Big PFC::hash_to_aes_key(const GT& w)
{
	Big m=pow((Big)2,S);
	return H2(w.g)%m;
}

Big PFC::hash_to_group(char *ID)
{
	Big m=H1(ID);
	return m%(*ord);
}

GT operator*(const GT& x,const GT& y)
{
	GT z=x;
	z.g*=y.g;
	return z; 
}

GT operator/(const GT& x,const GT& y)
{
	GT z=x;
	z.g/=y.g;
	return z; 
}

//
// spill precomputation on GT to byte array
//

int GT::spill(char *& bytes)
{
	int i,j,n=(1<<WINDOW_SIZE);
	int bytes_per_big=(MIRACL/8)*(get_mip()->nib-1);
	int len=n*6*bytes_per_big;
	ZZn2 a,b,c;
	Big x,y;

	if (etable==NULL) return 0;

	bytes=new char[len];
	for (i=j=0;i<n;i++)
	{
		etable[i].get(a,b,c);
		a.get(x,y);
		to_binary(x,bytes_per_big,&bytes[j],TRUE);
		j+=bytes_per_big;
		to_binary(y,bytes_per_big,&bytes[j],TRUE);
		j+=bytes_per_big;
		b.get(x,y);
		to_binary(x,bytes_per_big,&bytes[j],TRUE);
		j+=bytes_per_big;
		to_binary(y,bytes_per_big,&bytes[j],TRUE);
		j+=bytes_per_big;
		c.get(x,y);
		to_binary(x,bytes_per_big,&bytes[j],TRUE);
		j+=bytes_per_big;
		to_binary(y,bytes_per_big,&bytes[j],TRUE);
		j+=bytes_per_big;
	}
	delete [] etable; 
	etable=NULL;
	return len;
}

//
// restore precomputation for GT from byte array
//

void GT::restore(char *bytes)
{
	int i,j,n=(1<<WINDOW_SIZE);
	int bytes_per_big=(MIRACL/8)*(get_mip()->nib-1);
	int len=n*6*bytes_per_big;
	ZZn2 a,b,c;
	Big x,y;
	if (etable!=NULL) return;

	etable=new ZZn6[1<<WINDOW_SIZE];
	for (i=j=0;i<n;i++)
	{
		x=from_binary(bytes_per_big,&bytes[j]);
		j+=bytes_per_big;
		y=from_binary(bytes_per_big,&bytes[j]);
		j+=bytes_per_big;
		a.set(x,y);
		x=from_binary(bytes_per_big,&bytes[j]);
		j+=bytes_per_big;
		y=from_binary(bytes_per_big,&bytes[j]);
		j+=bytes_per_big;
		b.set(x,y);
		x=from_binary(bytes_per_big,&bytes[j]);
		j+=bytes_per_big;
		y=from_binary(bytes_per_big,&bytes[j]);
		j+=bytes_per_big;
		c.set(x,y);
		etable[i].set(a,b,c);
	}
	delete [] bytes;
}


G1 operator+(const G1& x,const G1& y)
{
	G1 z=x;
	z.g+=y.g;
	return z;
}

G1 operator-(const G1& x)
{
	G1 z=x;
	z.g=-z.g;
	return z;
}

//
// spill precomputation on G1 to byte array
//

int G1::spill(char *& bytes)
{
	int i,j,n=(1<<WINDOW_SIZE);
	int bytes_per_big=(MIRACL/8)*(get_mip()->nib-1);
	int len=n*2*bytes_per_big;
	Big x,y;

	if (mtable==NULL) return 0;

	bytes=new char[len];
	for (i=j=0;i<n;i++)
	{
		mtable[i].get(x,y);
		to_binary(x,bytes_per_big,&bytes[j],TRUE);
		j+=bytes_per_big;
		to_binary(y,bytes_per_big,&bytes[j],TRUE);
		j+=bytes_per_big;
	}
	delete [] mtable; 
	mtable=NULL;
	return len;
}

//
// restore precomputation for G1 from byte array
//

void G1::restore(char *bytes)
{
	int i,j,n=(1<<WINDOW_SIZE);
	int bytes_per_big=(MIRACL/8)*(get_mip()->nib-1);
	int len=n*2*bytes_per_big;
	Big x,y;
	if (mtable!=NULL) return;

	mtable=new ECn[1<<WINDOW_SIZE];
	for (i=j=0;i<n;i++)
	{
		x=from_binary(bytes_per_big,&bytes[j]);
		j+=bytes_per_big;
		y=from_binary(bytes_per_big,&bytes[j]);
		j+=bytes_per_big;
		mtable[i].set(x,y);
	}
	delete [] bytes;
}

G2 operator+(const G2& x,const G2& y)
{
	G2 z=x;
	z.g+=y.g;
	return z;
}

G2 operator-(const G2& x)
{
	G2 z=x;
	z.g=-z.g;
	return z;
}

//
// spill precomputation on G2 to byte array
//

int G2::spill(char *& bytes)
{
	int i,j,n=(1<<WINDOW_SIZE);
	int bytes_per_big=(MIRACL/8)*(get_mip()->nib-1);
	int len=n*6*bytes_per_big;
	ZZn3 x,y;
	ZZn a,b,c;

	if (mtable==NULL) return 0;

	bytes=new char[len];
	for (i=j=0;i<n;i++)
	{
		mtable[i].get(x,y);
		x.get(a,b,c);
		to_binary((Big)a,bytes_per_big,&bytes[j],TRUE);
		j+=bytes_per_big;
		to_binary((Big)b,bytes_per_big,&bytes[j],TRUE);
		j+=bytes_per_big;
		to_binary((Big)c,bytes_per_big,&bytes[j],TRUE);
		j+=bytes_per_big;
		y.get(a,b,c);
		to_binary((Big)a,bytes_per_big,&bytes[j],TRUE);
		j+=bytes_per_big;
		to_binary((Big)b,bytes_per_big,&bytes[j],TRUE);
		j+=bytes_per_big;
		to_binary((Big)c,bytes_per_big,&bytes[j],TRUE);
		j+=bytes_per_big;
	}
	delete [] mtable; 
	mtable=NULL;
	return len;
}

//
// restore precomputation for G2 from byte array
//

void G2::restore(char *bytes)
{
	int i,j,n=(1<<WINDOW_SIZE);
	int bytes_per_big=(MIRACL/8)*(get_mip()->nib-1);
	int len=n*6*bytes_per_big;
	ZZn3 x,y;
	ZZn a,b,c;
	if (mtable!=NULL) return;

	mtable=new ECn3[1<<WINDOW_SIZE];
	for (i=j=0;i<n;i++)
	{
		a=from_binary(bytes_per_big,&bytes[j]);
		j+=bytes_per_big;
		b=from_binary(bytes_per_big,&bytes[j]);
		j+=bytes_per_big;
		c=from_binary(bytes_per_big,&bytes[j]);
		j+=bytes_per_big;
		x.set(a,b,c);
		a=from_binary(bytes_per_big,&bytes[j]);
		j+=bytes_per_big;
		b=from_binary(bytes_per_big,&bytes[j]);
		j+=bytes_per_big;
		c=from_binary(bytes_per_big,&bytes[j]);
		j+=bytes_per_big;
		y.set(a,b,c);
		mtable[i].set(x,y);
	}
	delete [] bytes;
}

BOOL PFC::member(const GT& z)
{
	ZZn6 r=z.g;
	ZZn6 w=z.g;
	Big X=*x;
	if (!r.is_unitary()) return FALSE;
	if (r*conj(r)!=(ZZn6)1) return FALSE; // not unitary
	w.powq(*frob);
	if (X<0) r=powu(inverse(r),-X);
	else     r=powu(r,X);
	if (r==w) return TRUE;
	return FALSE;
}

GT PFC::pairing(const G2& x,const G1& y)
{
	GT z;
	z=miller_loop(x,y);
	z=final_exp(z);
	return z;
}

GT PFC::multi_pairing(int n,G2 **y,G1 **x)
{
	GT z;
	z=multi_miller(n,y,x);
	z=final_exp(z);
	return z;

}

int PFC::precomp_for_mult(G1& w,BOOL small)
{
	ECn v=w.g;
	int i,j,k,bp,is,t;
	if (small) t=MR_ROUNDUP(2*S,WINDOW_SIZE);
	else       t=MR_ROUNDUP(bits(*ord),WINDOW_SIZE);
	w.mtable=new ECn[1<<WINDOW_SIZE];
	w.mtable[1]=v;
	w.mtbits=t;
	for (j=0;j<t;j++)
        v+=v;
    k=1;
    for (i=2;i<(1<<WINDOW_SIZE);i++)
    {
        if (i==(1<<k))
        {
            k++;
			normalise(v);
			w.mtable[i]=v;     
            for (j=0;j<t;j++)
				v+=v;
            continue;
        }
        bp=1;
        for (j=0;j<k;j++)
        {
            if (i&bp)
			{
				is=1<<j;
				w.mtable[i]+=w.mtable[is];
			}
            bp<<=1;
        }
        normalise(w.mtable[i]);
    }
	return (1<<WINDOW_SIZE);
}

int PFC::precomp_for_mult(G2& w,BOOL small)
{
	ECn3 v=w.g;
	ZZn3 x,y;
	int i,j,k,bp,is,t;
	if (small) t=MR_ROUNDUP(2*S,WINDOW_SIZE);
	else       t=MR_ROUNDUP(bits(*ord),WINDOW_SIZE);
	w.mtable=new ECn3[1<<WINDOW_SIZE];
	w.mtable[1]=v;
	w.mtbits=t;
	for (j=0;j<t;j++)
        v+=v;
    k=1;
    for (i=2;i<(1<<WINDOW_SIZE);i++)
    {
        if (i==(1<<k))
        {
            k++;
			w.mtable[i]=v;     
            for (j=0;j<t;j++)
				v+=v;
            continue;
        }
        bp=1;
        for (j=0;j<k;j++)
        {
            if (i&bp)
			{
				is=1<<j;
				w.mtable[i]+=w.mtable[is];
			}
            bp<<=1;
        }
    }
	return (1<<WINDOW_SIZE);
}

int PFC::precomp_for_power(GT& w,BOOL small)
{
	ZZn6 v=w.g;
	int i,j,k,bp,is,t;
	if (small) t=MR_ROUNDUP(2*S,WINDOW_SIZE);
	else       t=MR_ROUNDUP(bits(*ord),WINDOW_SIZE);
	w.etable=new ZZn6[1<<WINDOW_SIZE];
	w.etable[0]=1;
	w.etable[1]=v;
	w.etbits=t;
	for (j=0;j<t;j++)
        v*=v;
    k=1;

    for (i=2;i<(1<<WINDOW_SIZE);i++)
    {
        if (i==(1<<k))
        {
            k++;
			w.etable[i]=v;     
            for (j=0;j<t;j++)
				v*=v;
            continue;
        }
        bp=1;
		w.etable[i]=1;
        for (j=0;j<k;j++)
        {
            if (i&bp)
			{
				is=1<<j;
				w.etable[i]*=w.etable[is];
			}
            bp<<=1;
        }
    }
	return (1<<WINDOW_SIZE);
}
