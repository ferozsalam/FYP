/*
 *    MIRACL  C++ Implementation file ecn3.cpp
 *
 *    AUTHOR  : M. Scott
 *  
 *    PURPOSE : Implementation of class ECn3  (Elliptic curves over n^3)
 *
 * WARNING: This class has been cobbled together for a specific use with
 * the MIRACL library. It is not complete, and may not work in other 
 * applications
 *
 *    Copyright (c) 2006 Shamus Software Ltd.
 */

#include "ecn3.h"

using namespace std;

void ECn3::get(ZZn3& a,ZZn3& b)
{/*norm();*/ a=x; b=y;}

void ECn3::get(ZZn3& a)
{/*norm();*/ a=x;}
/*
#ifndef MR_AFFINE_ONLY
void ECn3::getZ(ZZn3& a)
{a=z;}
void ECn3::get(ZZn3& a,ZZn3& b,ZZn3& c)
{
	a=x;b=y;
	if (marker==MR_EPOINT_GENERAL) c=z;
	else c=(ZZn)1;
}

void ECn3::set(const ZZn3& xx,const ZZn3& yy,const ZZn3& zz)
{
	x=xx;
	y=yy;
	z=zz;
	if (z==(ZZn)1) marker=MR_EPOINT_NORMALIZED;
	else		   marker=MR_EPOINT_GENERAL;
}
#endif
*/
BOOL ECn3::set(const ZZn3& xx,const ZZn3& yy)
{ 
  int qnr;
  ZZn3 w;

  w=rhs(xx);
  if (yy*yy!=w) return FALSE;
  x=xx;
  y=yy;
  marker=MR_EPOINT_NORMALIZED;
  return TRUE;
}

BOOL ECn3::set(const ZZn3& xx)
{ 
	ZZn3 w;

	w=rhs(xx);

	if (!w.iszero())
	{
		w=sqrt(w); 
		if (w.iszero()) return FALSE;
	}
	x=xx;
	y=w;

	marker=MR_EPOINT_NORMALIZED;
	return TRUE;
}
/*
void ECn3::norm(void)
{ // normalize a point   
#ifndef MR_AFFINE_ONLY
    if (marker!=MR_EPOINT_GENERAL) return;
	ZZn3 t;
	z=inverse(z);
	t=z;
	z*=z;
	x*=z;
	z*=t;
	y*=z;
	z=1;
	marker=MR_EPOINT_NORMALIZED;
#endif
}
*/

ECn3 operator-(const ECn3& a) 
{ECn3 w; 
 if (a.marker!=MR_EPOINT_INFINITY) 
 {
	 w.x=a.x; 
	 w.y=-a.y; 
	 w.marker=a.marker;
//#ifndef MR_AFFINE_ONLY
//	 if (w.marker==MR_EPOINT_GENERAL) w.z=a.z;
//#endif 
 } 
 return w; 
}  

ECn3& ECn3::operator*=(const Big& k)
{
    int i,j,n,nb,nbs,nzs;
    ECn3 p2,pt,t[11];
    Big h,kk;

    if (k==0)
    {
        clear();
        return *this;
    }
    if (k==1)
    {
        return (*this);
    }

//	norm();
    pt=*this;
    kk=k;
    if (kk<0)
    {
        pt=-pt;
        kk=-kk;
    }
    h=3*kk;

// This is not optimal!

    p2=pt+pt; //p2.norm(); 
    t[0]=pt;
    for (i=1;i<=10;i++)
	{
        t[i]=t[i-1]+p2;
		//t[i].norm();
	}

// Left to Right method

    nb=bits(h);
    for (i=nb-2;i>=1;)
    {
        n=naf_window(kk,h,i,&nbs,&nzs,11);
        for (j=0;j<nbs;j++) pt+=pt;
        if (n>0) pt+=t[n/2];
        if (n<0) pt-=t[(-n)/2];
        i-=nbs;
        if (nzs)
        {
            for (j=0;j<nzs;j++) pt+=pt;
            i-=nzs;
        }
    }
    *this=pt;
    return *this;
}

ECn3 operator*(const Big& r,const ECn3& P)
{
    ECn3 T=P;
    T*=r;
    return T;
}

ostream& operator<<(ostream& s,ECn3& b)
{
    ZZn3 x,y;
    if (b.iszero())
        s << "(Infinity)";
    else
    {
        b.get(x,y);
        s << "(" << x << "," << y << ")";
    }
    return s;
}

ECn3 operator+(const ECn3& a,const ECn3& b)
{ECn3 c=a; c+=b; return c;}

ECn3 operator-(const ECn3& a,const ECn3& b)
{ECn3 c=a; c-=b; return c;}

ECn3& ECn3::operator-=(const ECn3& z)
{ECn3 t=(-z); *this+=t; return *this; }

ECn3& ECn3::operator+=(const ECn3& z)
{
    ZZn3 lam;
    add(z,lam/*,NULL,NULL*/);
    return *this;
}

int ECn3::add(const ECn3& W,ZZn3& lam/*,ZZn3 *ex1,ZZn3 *ex2*/)
{
    miracl *mip=get_mip();
    int twist=mip->TWIST;
    int qnr=mip->cnr;

    if (marker==MR_EPOINT_INFINITY)
    {
        *this=W;
        return MR_ADD;
    }
    if (W.marker==MR_EPOINT_INFINITY)
    {
        return MR_ADD;
    }

//#ifndef MR_AFFINE_ONLY
//    if (mr_mip->coord==MR_AFFINE)
//    {
//#endif
		if (x!=W.x)
		{
			ZZn3 t=y;  t-=W.y;
			ZZn3 t2=x; t2-=W.x;    
			lam=t; lam/=t2;

			x+=W.x; t=lam; t*=t; t-=x; x=t;   
			y=W.x; y-=x; y*=lam; y-=W.y;   
			marker=MR_EPOINT_NORMALIZED;    
			return MR_ADD;
		}
		else
		{
			if (y!=W.y || y.iszero())
			{
				clear();
				lam=one();       // any non-zero value
				return 0;     
			}
			ZZn3 t=x;
			ZZn3 t2=x;

     //   lam=(3*(x*x)+getA())/(y+y);
			lam=x;
			lam*=lam;
			lam*=3;

			if (twist==MR_QUADRATIC)	lam+=qnr*qnr*getA();
			else						lam+=getA();
		
			lam/=(y+y);    
			t2+=x;
			x=lam;
			x*=x;
			x-=t2;
         
			t-=x;
			t*=lam;
			t-=y;
			y=t;   
			marker=MR_EPOINT_NORMALIZED;    
			return MR_DOUBLE;			
		}
/*
#ifndef MR_AFFINE_ONLY
    }
	int iA;
	BOOL Doubling;
	ZZn3 t1,t2,t3;
    ZZn3 Yzzz;

	t3=W.x;
	Yzzz=W.y;

	Doubling=FALSE;
	if (this==&W) Doubling=TRUE;

	if (!Doubling)
	{
		if (W.marker!=MR_EPOINT_NORMALIZED)
		{
			mr_berror(_MIPP_ MR_ERR_BAD_PARAMETERS);
			MR_OUT
			return 0;
		}
		if (marker!=MR_EPOINT_NORMALIZED)
		{
			t1=z; t1*=t1;
			t3*=t1;
			t1*=z;
			Yzzz*=t1;
		}
		if (t3==x)
		{
			if (Yzzz!=y || y==0)
			{
				clear();
				lam=1;
			}
			else Doubling=TRUE;
		}
	}
	if (!Doubling)
    { // Addition 
		t3-=x;
		lam=Yzzz-y;
		if (marker==MR_EPOINT_NORMALIZED) z=t3;
		else z*=t3;
		t1=t3; t1*=t1;
		Yzzz=t1*t3;
		t1*=x;
		t3=t1;
		t3+=t3;
		x=lam; x*=x;
		x-=t3;
		x-=Yzzz;
		t1-=x;
		t1*=lam;
		Yzzz*=y;
		y=t1-Yzzz;
	}
    else
    { // doubling 
		t3=y; t3*=t3;
		iA=get_mip()->Asize;
		if (iA!=0)
		{
			if (marker==MR_EPOINT_NORMALIZED) t1=1;
			else {t1=z; t1*=t1;}
			if (ex2!=NULL) *ex2=t1;
			if (iA==-3)
			{
				if (twist==MR_QUADRATIC) t1*=qnr;
				lam=x-t1;
				t1+=x;
				lam*=t1;
				t2=lam; t2+=t2;
				lam+=t2;
			}
			else
			{
				lam=x; lam*=lam;
				t2=lam; t2+=t2;
				lam+=t2;
				if (twist==MR_QUADRATIC) t1*=qnr;
				t1*=t1;
				if (iA==1)
				{
					if (iA<MR_TOOBIG) t1*=iA;
					else t1*=getA();
				}
				lam+=t1;
			}
		}
		else
		{
			lam=x; lam*=lam;
			t2=lam; t2+=lam;
			lam+=t2;
		}

		t1=t3*x;
		t1+=t1;
		t1+=t1;
		x=lam; x*=x;
		t2=t1+t1;
		x-=t2;
		if (marker==MR_EPOINT_NORMALIZED) z=y;
		else z*=y;
		z+=z;
		t3+=t3;
		if (ex1!=NULL) *ex1=t3;
		t3*=t3;
		t3+=t3;
		t1-=x;
		y=t1*lam;
		y-=t3;
	}
     
	marker=MR_EPOINT_GENERAL;
	if (Doubling) return MR_DOUBLE;
	return MR_ADD;
#endif
*/
}

#ifndef MR_NO_ECC_MULTIADD

ECn3 mul(const ECn3& P,const Big& a,const ECn3& Q,const Big& b)
{
	ECn3 X=P;
	ECn3 Y=Q;
	Big A=a;
	Big B=b;
	Big A3,B3;
	ECn3 S,D,R;

	int e1,e2,h1,h2,nb,t;
	if (A<0) { A=-A; X=-X;}
	if (B<0) { B=-B; Y=-Y;}
// joint sparse form
	jsf(A,B,A3,A,B3,B);
//	X.norm(); Y.norm();
	S=X+Y;
	D=Y-X;
//	S.norm(); D.norm();

	if (A3>B3) nb=bits(A3)-1;
	else       nb=bits(B3)-1;

	while (nb>=0)
	{
		R+=R;
		e1=h1=e2=h2=0;
		t=0;
		if (bit(A,nb))  {e2=1; t+=8;}
		if (bit(A3,nb)) {h2=1; t+=4;}
		if (bit(B,nb))  {e1=1; t+=2;}
		if (bit(B3,nb)) {h1=1; t+=1;}

		if (t==1 || t==13) R+=Y;
		if (t==2 || t==14) R-=Y;
		if (t==4 || t==7)  R+=X;
		if (t==8 || t==11) R-=X;
		if (t==5)  R+=S;
		if (t==10) R-=S;
		if (t==9)  R+=D;
		if (t==6)  R-=D;
		nb-=1;
	}
//	R.norm();
	return R;
}

#ifndef MR_STATIC

ECn3 mul(int n,ECn3* P,const Big* b)
{
    int k,j,i,m,nb,ea;
    ECn3 *G;
    ECn3 R;
    m=1<<n;
    G=new ECn3[m];

 // precomputation
    
    for (i=0,k=1;i<n;i++)
    {
        for (j=0; j < (1<<i) ;j++)
        {
            if (j==0)   G[k]=P[i];
            else        G[k]=G[j]+P[i];      
            k++;
        }
    }

    nb=0;
    for (j=0;j<n;j++) 
        if ((k=bits(b[j]))>nb) nb=k;

    for (i=nb-1;i>=0;i--) 
    {
        ea=0;
        k=1;
        for (j=0;j<n;j++)
        {
            if (bit(b[j],i)) ea+=k;
            k<<=1;
        }
        R+=R;;
        if (ea!=0) R+=G[ea];
    }
    delete [] G;
//	R.norm();
    return R;
}

#endif
#endif
