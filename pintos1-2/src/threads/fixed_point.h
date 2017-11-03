#define F (1 << 14)	// fixed point 1
#define INT_MAX ((1 << 31) - 1)
#define INT_MIN (-(1 << 31))
// x and y denote fixed_point numbers in 17.14 format
// n is an integer

int int_to_fp (int n);			// integer to fixed point
int fp_to_int_round (int x);	// FP to int (rounding off)
int fp_to_int (int x);			// FP to int (truncatin)
int add_fp (int x, int y);		// add between FPs
int add_mixed (int x, int n);	// add between int and FP
int sub_fp (int x, int y);		// sub between FPs
int sub_mixed (int x, int n);	// sub between int and FP
int mult_fp (int x, int y);		// multi between FPs
int mult_mixed (int x, int n);	// multi between int and FP
int div_fp (int x, int y);		// div between FPs
int div_mixed (int x, int n);	// div between int and FP


int
int_to_fp (int n)
{
	return n*F;
}

int 
fp_to_int_round (int x)
{
	return x/F;
}

int 
fp_to_int (int x)
{
	return (x>=0)? (x+F/2)/F : (x-F/2)/F;
}

int 
add_fp (int x, int y)
{
	return x+y;
}

int 
add_mixed (int x, int n)
{
	return x+n*F;
}

int 
sub_fp (int x, int y)
{
	return x-y;
}

int 
sub_mixed (int x, int n)
{
	return x-n*F;
}

int
mult_fp (int x, int y)
{
	return ((int64_t)x) * y/F;
}


int 
mult_mixed (int x, int n)
{
	return x*n;
}

int 
div_fp (int x, int y)
{
	return ((int64_t)x) *F/y;
}

int 
div_mixed (int x, int n)
{
	return x/n;
}

