// Copyright (c) 2014 The Magi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef MAGI_MATH_H
#define MAGI_MATH_H

double exp_n(double xt);
double exp_n2(double x1, double x2);
void gauleg(double x1, double x2, double x[], double w[], int n);
double GaussianQuad_N(double func(const double), const double a2, const double b2, int NptGQ);
double swit_(double wvnmb);
uint32_t sw_(int nnounce, int divs);



#endif