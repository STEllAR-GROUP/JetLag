#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__license__ = """ 
Copyright (c) 2020 Shahrzad Shirzad
Copyright (c) 2020 R. Tohid

Distributed under the Boost Software License, Version 1.0. (See accompanying
file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
"""

import csv
import datetime
import glob
import math
import matplotlib.tri as mtri
import numpy as np
import random

from matplotlib import pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from mpl_toolkits import mplot3d

now = datetime.datetime.now()
date_str=now.strftime("%Y-%m-%d-%H%M")
simdsize=4

#hpx_dir='/home/shahrzad/repos/Blazemark/data/matrix/dmatdmatadd/01-04-2019-1027'
hpx_dir='/home/shahrzad/repos/Blazemark/data/matrix/06-13-2019/marvin/'
openmp_dir_2='/home/shahrzad/repos/Blazemark/data/openmp/04-27-2019/'
openmp_dir_1='/home/shahrzad/repos/Blazemark/data/openmp/all/'


perf_directory='/home/shahrzad/repos/Blazemark/data/performance_plots/matrix/06-13-2019/marvin'


def create_dict(directory):
    thr=[]
    repeats=[]
    data_files=glob.glob(directory+'/*.dat')
    benchmark=''
    benchmarks=[]
    chunk_sizes=[]
    block_sizes=[]
    for filename in data_files:
        (repeat, benchmark, th, runtime, chunk_size, block_size_row, block_size_col) = filename.split('/')[-1].replace('.dat','').split('-')         
        if benchmark not in benchmarks:
                benchmarks.append(benchmark)                
        if int(th) not in thr:
            thr.append(int(th))
        if int(repeat) not in repeats:
            repeats.append(int(repeat)) 
        if int(chunk_size) not in chunk_sizes:
            chunk_sizes.append(int(chunk_size))
        if block_size_row+'-'+block_size_col not in block_sizes:
            block_sizes.append(block_size_row+'-'+block_size_col)
                  
    thr.sort()
    benchmarks.sort()      
    repeats.sort()      
    chunk_sizes.sort()
    block_sizes.sort()
    mat_sizes={}
    
    d_all={}   
    d={}
    for benchmark in benchmarks:  
        d_all[benchmark]={}
        d[benchmark]={}
        for th in thr:
            d_all[benchmark][th]={}
            d[benchmark][th]={}
            for r in repeats:
                d_all[benchmark][th][r]={}        
                for bs in block_sizes:
                    d_all[benchmark][th][r][bs]={}
                    d[benchmark][th][bs]={}
                    for cs in chunk_sizes:
                        d_all[benchmark][th][r][bs][cs]={}
                        d[benchmark][th][bs][cs]={}

                                            
    data_files.sort()        
    for filename in data_files:                
        stop=False
        f=open(filename, 'r')
                 
        result=f.readlines()[3:]
        benchmark=filename.split('/')[-1].split('-')[1]
        th=int(filename.split('/')[-1].split('-')[2])       
        repeat=int(filename.split('/')[-1].split('-')[0])  
        chunk_size=int(filename.split('/')[-1].split('-')[4]) 
        block_size=filename.split('/')[-1].split('-')[5]+'-'+filename.split('/')[-1].split('-')[6][0:-4]
        size=[]
        mflops=[]    
        for r in result:        
            if "N=" in r:
                stop=True
            if not stop:
                size.append(int(r.strip().split(' ')[0]))
                mflops.append(float(r.strip().split(' ')[-1]))
            
        d_all[benchmark][th][repeat][block_size][chunk_size]['size']=size
        d_all[benchmark][th][repeat][block_size][chunk_size]['mflops']=mflops
        if 'size' not in d[benchmark][th][block_size][chunk_size].keys():
            d[benchmark][th][block_size][chunk_size]['size']=size
            d[benchmark][th][block_size][chunk_size]['mflops']=[0]*len(size)
        if len(repeats)==1 and repeat==1:
            d[benchmark][th][block_size][chunk_size]['mflops']=mflops
        elif len(repeats)>1 and repeat!=1:
            d[benchmark][th][block_size][chunk_size]['mflops']+=mflops/(len(repeats)-1)
        else:
            print("errrrrorrrrrrrrrrrr")
        if benchmark not in mat_sizes.keys():
            mat_sizes[benchmark]=size
    return (d, chunk_sizes, block_sizes, thr, benchmarks, mat_sizes)      

#######################################################
def create_dict_relative(directory):
    thr=[]
    repeats=[]
    data_files=glob.glob(directory+'/*.dat')
    benchmark=''
    benchmarks=[]
    chunk_sizes=[]
    block_sizes={}
    mat_sizes={}
    
    for filename in data_files:
        (repeat, benchmark, th, runtime, chunk_size, block_size_row, block_size_col, mat_size) = filename.split('/')[-1].replace('.dat','').split('-')         
        mat_size=mat_size.split(',')[0]
        if benchmark not in benchmarks:
                benchmarks.append(benchmark)   
                mat_sizes[benchmark]=[]
                block_sizes[benchmark]=[]
        if int(mat_size) not in mat_sizes[benchmark]:
            mat_sizes[benchmark].append(int(mat_size))
        if int(th) not in thr:
            thr.append(int(th))
        if int(repeat) not in repeats:
            repeats.append(int(repeat)) 
        if block_size_row+'-'+block_size_col not in block_sizes[benchmark]:
            block_sizes[benchmark].append(block_size_row+'-'+block_size_col)
        if int(chunk_size) not in chunk_sizes:
            chunk_sizes.append(int(chunk_size))
                  
    thr.sort()
    repeats.sort()      
    chunk_sizes.sort()
    benchmarks.sort()   
    
    d_all={}   
    d={}
    for benchmark in benchmarks:  
        mat_sizes[benchmark].sort()
        block_sizes[benchmark].sort()
        d_all[benchmark]={}
        d[benchmark]={}
        for th in thr:
            d_all[benchmark][th]={}
            d[benchmark][th]={}
            for r in repeats:
                d_all[benchmark][th][r]={}        
                for bs in block_sizes[benchmark]:
                    d_all[benchmark][th][r][bs]={}
                    d[benchmark][th][bs]={}
                    for cs in chunk_sizes:
                        d_all[benchmark][th][r][bs][cs]={}
                        d[benchmark][th][bs][cs]={}
                        d[benchmark][th][bs][cs]['size']=mat_sizes[benchmark]
                        d[benchmark][th][bs][cs]['mflops']=[0]*len(mat_sizes[benchmark])
                        d_all[benchmark][th][r][bs][cs]['size']=mat_sizes[benchmark]
                        d_all[benchmark][th][r][bs][cs]['mflops']=[0]*len(mat_sizes[benchmark])

                                            
    data_files.sort()        
    for filename in data_files:                
        stop=False
        f=open(filename, 'r')
                 
        result=f.readlines()[3:]
        benchmark=filename.split('/')[-1].split('-')[1]
        th=int(filename.split('/')[-1].split('-')[2])       
        repeat=int(filename.split('/')[-1].split('-')[0])  
        chunk_size=int(filename.split('/')[-1].split('-')[4])         
        block_size=filename.split('/')[-1].split('-')[5]+'-'+filename.split('/')[-1].split('-')[6].replace('.dat','')  
        for r in result:        
            if "N=" in r:
                stop=True
            if not stop:
                s=mat_sizes[benchmark].index(int(r.strip().split(' ')[0]))
                d_all[benchmark][th][repeat][block_size][chunk_size]['mflops'][s]=float(r.strip().split(' ')[-1])

#        if 'size' not in d[benchmark][th][block_size][chunk_size].keys():
#            d[benchmark][th][block_size][chunk_size]['size']=size
#            d[benchmark][th][block_size][chunk_size]['mflops']=[0]*len(size)
        if len(repeats)==1 and repeat==1:
            d[benchmark][th][block_size][chunk_size]['mflops']=d_all[benchmark][th][repeat][block_size][chunk_size]['mflops']
        elif len(repeats)>1 and repeat!=1:
            d[benchmark][th][block_size][chunk_size]['mflops']+=d_all[benchmark][th][repeat][block_size][chunk_size]['mflops']/(len(repeats)-1)
        else:
            print("errrrrorrrrrrrrrrrr")

    return (d, chunk_sizes, block_sizes, thr, benchmarks, mat_sizes)  
###########################################################################
def create_dict_relative_norepeat(directories):
    thr={}
    data_files=[]
    
    for directory in directories:
        [data_files.append(i) for i in glob.glob(directory+'/*.dat')]
    benchmark=''
    benchmarks=[]
    chunk_sizes=[]
    block_sizes={}
    mat_sizes={}
    nodes=[]
    
    for filename in data_files:
        (node, benchmark, th, runtime, chunk_size, block_size_row, block_size_col, mat_size) = filename.split('/')[-1].replace('.dat','').split('-')         
        mat_size=mat_size.split(',')[0]
        if benchmark not in benchmarks:
                benchmarks.append(benchmark)   
                mat_sizes[benchmark]=[]
                block_sizes[benchmark]=[]
        if node not in nodes:
            thr[node]=[]
        if int(mat_size) not in mat_sizes[benchmark]:
            mat_sizes[benchmark].append(int(mat_size))
        if int(th) not in thr[node]:
            thr[node].append(int(th))        
        if block_size_row+'-'+block_size_col not in block_sizes[benchmark]:
            block_sizes[benchmark].append(block_size_row+'-'+block_size_col)
        if chunk_size=='':
            chunk_size=-1
        if int(chunk_size) not in chunk_sizes:
            chunk_sizes.append(int(chunk_size))
        if node not in nodes:
            nodes.append(node)
                  
    [thr[node].sort() for node in thr.keys()]
    nodes.sort()      
    chunk_sizes.sort()
    benchmarks.sort()   
    
    d={}
    for node in nodes:
        d[node]={}
        for benchmark in benchmarks:  
            mat_sizes[benchmark].sort()
            block_sizes[benchmark].sort()
            d[node][benchmark]={}
           
            for th in thr[node]:
                d[node][benchmark][th]={}
                for bs in block_sizes[benchmark]:
                    d[node][benchmark][th][bs]={}
                    for cs in chunk_sizes:
                        d[node][benchmark][th][bs][cs]={}
                        d[node][benchmark][th][bs][cs]['size']=mat_sizes[benchmark]
                        d[node][benchmark][th][bs][cs]['mflops']=[0]*len(mat_sizes[benchmark])
                        

                                            
    data_files.sort()        
    for filename in data_files:                
        stop=False
        f=open(filename, 'r')
                 
        result=f.readlines()[3:]
        (node, benchmark, th, runtime, chunk_size, block_size_row, block_size_col, mat_size) = filename.split('/')[-1].replace('.dat','').split('-')         
        th=int(th)       
        if chunk_size=='':
            chunk_size=-1
        chunk_size=int(chunk_size)         
        for r in result:        
            if "N=" in r:
                stop=True
            if not stop:
                s=mat_sizes[benchmark].index(int(r.strip().split(' ')[0]))
                d[node][benchmark][th][block_size_row+'-'+block_size_col][chunk_size]['mflops'][s]=float(r.strip().split(' ')[-1])

    return (d, chunk_sizes, block_sizes, thr, benchmarks, mat_sizes)  

###########################################################################
def create_dict_relative_norepeat_counters_onebyone(directory):
    thr=[]
    data_files=glob.glob(directory+'/*.dat')
    benchmark=''
    benchmarks=[]
    chunk_sizes=[]
    block_sizes={}
    mat_sizes={}
    nodes=[]
    
    for filename in data_files:
        (node, benchmark, th, runtime, chunk_size, block_size_row, block_size_col, mat_size) = filename.split('/')[-1].replace('.dat','').split('-')         
        mat_size=mat_size.split(',')[0]
        if benchmark not in benchmarks:
                benchmarks.append(benchmark)   
                mat_sizes[benchmark]=[]
                block_sizes[benchmark]=[]
        if int(mat_size) not in mat_sizes[benchmark]:
            mat_sizes[benchmark].append(int(mat_size))
        if int(th) not in thr:
            thr.append(int(th))        
        if block_size_row+'-'+block_size_col not in block_sizes[benchmark]:
            block_sizes[benchmark].append(block_size_row+'-'+block_size_col)
        if int(chunk_size) not in chunk_sizes:
            chunk_sizes.append(int(chunk_size))
        if node not in nodes:
            nodes.append(node)
                  
    thr.sort()
    nodes.sort()      
    chunk_sizes.sort()
    benchmarks.sort()   
    repeats=5
    
    d={}
    for node in nodes:
        d[node]={}
        for benchmark in benchmarks:  
            mat_sizes[benchmark].sort()
            block_sizes[benchmark].sort()
            d[node][benchmark]={}
           
            for th in thr:
                d[node][benchmark][th]={}
                for bs in block_sizes[benchmark]:
                    d[node][benchmark][th][bs]={}
                    for cs in chunk_sizes:
                        d[node][benchmark][th][bs][cs]={}
                        d[node][benchmark][th][bs][cs]['size']=mat_sizes[benchmark]
                        d[node][benchmark][th][bs][cs]['mflops']=[0]*len(mat_sizes[benchmark])
                        d[node][benchmark][th][bs][cs]['counters']=[0]*len(mat_sizes[benchmark])

    data_files.sort()        
    for filename in data_files:                
        f=open(filename, 'r')
                 
        results=f.read()
        (node, benchmark, th, runtime, chunk_size, block_size_row, block_size_col, mat_size) = filename.split('/')[-1].replace('.dat','').split('-')         
        th=int(th)       
        cs=int(chunk_size)     
        counters_avg={'idle_rate':[0]*th, 'average_time':[0]*th, 'cumulative_overhead_time':[0]*th, 'cumulative_count':[0]*th, 'average_overhead_time':[0]*th, 'papi_tca':[0]*th, 'papi_tcm':[0]*th}
        s=mat_sizes[benchmark].index(int(mat_size))

        bs=block_size_row+'-'+block_size_col
        mflops=float((results.split(' '+mat_size+' ')[1].split('\n')[0]).strip())
        d[node][benchmark][th][bs][cs]['mflops'][s]=mflops
        s=mat_sizes[benchmark].index(int(mat_size))
        d[node][benchmark][th][bs][cs]['counters'][s]={}
        d[node][benchmark][th][bs][cs]['counters'][s]['ind']=[]
        d[node][benchmark][th][bs][cs]['counters'][s]['avg']={}
        
        reps=results.split('Done')[1:]
        for rep in reps[1:-1]:
            counters_ind={'idle_rate':[0]*th, 'average_time':[0]*th, 'cumulative_overhead_time':[0]*th, 'cumulative_count':[0]*th, 'average_overhead_time':[0]*th,'papi_tca':[0]*th, 'papi_tcm':[0]*th}            

            rep_lines=rep.split('Initialization')[0].split('\n')   
            for r in rep_lines:
                if 'idle-rate' in r and 'pool' in r:
                    idle_rate=float(r.strip().split(',')[-2])/100
                    th_num=int(r.strip().split('thread#')[1].split('}')[0])
                    counters_ind['idle_rate'][th_num]=idle_rate
                    counters_avg['idle_rate'][th_num]+=idle_rate
                elif 'cumulative-overhead' in r and 'pool' in r:
                    cumulative_overhead=float(r.strip().split(',')[-2])/1000
                    th_num=int(r.strip().split('thread#')[1].split('}')[0])
                    counters_ind['cumulative_overhead_time'][th_num]=cumulative_overhead
                    counters_avg['cumulative_overhead_time'][th_num]+=cumulative_overhead
                elif 'average-overhead' in r and 'pool' in r:
                    average_overhead=float(r.strip().split(',')[-2])/1000
                    th_num=int(r.strip().split('thread#')[1].split('}')[0])
                    counters_ind['average_overhead_time'][th_num]=average_overhead   
                    counters_avg['average_overhead_time'][th_num]+=average_overhead     
                elif 'average,' in r and 'pool' in r:
                    average_time=float(r.strip().split(',')[-2])/1000
                    th_num=int(r.strip().split('thread#')[1].split('}')[0])
                    counters_ind['average_time'][th_num]=average_time
                    counters_avg['average_time'][th_num]+=average_time
                elif 'cumulative,' in r and 'pool' in r:
                    cumulative=float(r.strip().split(',')[-1])
                    th_num=int(r.strip().split('thread#')[1].split('}')[0])
                    counters_ind['cumulative_count'][th_num]=cumulative
                    counters_avg['cumulative_count'][th_num]+=cumulative
                elif 'PAPI_L2_TCA' in r :
                    papi_tca=float(r.strip().split(',')[-1])
                    th_num=int(r.strip().split('thread#')[1].split('}')[0])
                    counters_ind['papi_tca'][th_num]=papi_tca
                    counters_avg['papi_tca'][th_num]+=papi_tca
                elif 'PAPI_L2_TCM' in r :
                    papi_tca=float(r.strip().split(',')[-1])
                    th_num=int(r.strip().split('thread#')[1].split('}')[0])
                    counters_ind['papi_tcm'][th_num]=papi_tca
                    counters_avg['papi_tcm'][th_num]+=papi_tca

                        
            d[node][benchmark][th][bs][cs]['counters'][s]['ind'].append(counters_ind)
        for counter in counters_avg.keys():
            counters_avg[counter]=[counters_avg[counter][thread]/repeats for thread in range(th)]
        d[node][benchmark][th][bs][cs]['counters'][s]['avg']=counters_avg


    return (d, chunk_sizes, block_sizes, thr, benchmarks, mat_sizes)  
#############################################################################
    
def create_dict_openmp(directory):
    thr=[]
    repeats=[]
    data_files=glob.glob(directory+'/*.dat')
    benchmark=''
    benchmarks=[]
    for filename in data_files:
        (repeat, benchmark, th, runtime) = filename.split('/')[-1].replace('.dat','').split('-')         
        if benchmark not in benchmarks:
                benchmarks.append(benchmark)                
        if int(th) not in thr:
            thr.append(int(th))
        if int(repeat) not in repeats:
            repeats.append(int(repeat))          
                  
    thr.sort()
    benchmarks.sort()      
    repeats.sort()      
    
    d_all={}   
    d={}
    for benchmark in benchmarks:  
        d_all[benchmark]={}
        d[benchmark]={}
        for th in thr:
            d_all[benchmark][th]={}
            d[benchmark][th]={}
            for r in repeats:
                d_all[benchmark][th][r]={}        
                                            
    data_files.sort()        
    for filename in data_files:                
        stop=False
        f=open(filename, 'r')
                 
        result=f.readlines()[3:]
        benchmark=filename.split('/')[-1].split('-')[1]
        th=int(filename.split('/')[-1].split('-')[2])       
        repeat=int(filename.split('/')[-1].split('-')[0])        
        size=[]
        mflops=[]    
        for r in result:        
            if "N=" in r:
                stop=True
            if not stop:
                size.append(int(r.strip().split(' ')[0]))
                mflops.append(float(r.strip().split(' ')[-1]))
            
        d_all[benchmark][th][repeat]['size']=size
        d_all[benchmark][th][repeat]['mflops']=mflops
 
        
    for benchmark in benchmarks:
        for th in thr:
            d[benchmark][th]['size']=d_all[benchmark][th][1]['size']
            mflops=[0]*len(d[benchmark][th]['size'])    
            if max(repeats)==1:
                if 'mflops' in d_all[benchmark][th][1].keys():
                    mflops=d_all[benchmark][th][repeats[0]]['mflops']
                    d[benchmark][th]['mflops']=mflops
            else:
                for r in repeats[1:]:
                    mflops=[mflops[i]+d_all[benchmark][th][r]['mflops'][i] for i in range(len(mflops))]                        
                    d[benchmark][th]['mflops']=[x/float(max(repeats)-1) for x in mflops]
    return d                           

def create_dict_reference(directory,runtime='openmp'):
    thr=[]
    nodes=[]
#    data_files=glob.glob(directory+'/*.dat')
    data_files=[]
    
    [data_files.append(i) for i in glob.glob(directory+'/*.dat') if runtime in i.split('/')[-1]]
    benchmark=''
    benchmarks=[]
    for filename in data_files:
        try:
            (node, benchmark, th) = filename.split('/')[-1].replace('.dat','').split('-')   
        except:
            (node, benchmark, th, ref) = filename.split('/')[-1].replace('.dat','').split('-')  
        if benchmark not in benchmarks:
                benchmarks.append(benchmark)                
        if int(th) not in thr:
            thr.append(int(th))
        if node not in nodes:
            nodes.append(node)        
                  
    thr.sort()
    benchmarks.sort()      
    nodes.sort()      
    
    d_all={}   
    for node in nodes:
        d_all[node]={}
        for benchmark in benchmarks:  
            d_all[node][benchmark]={}
            for th in thr:
                d_all[node][benchmark][th]={}     
                                            
    data_files.sort()        
    for filename in data_files:                
        stop=False
        f=open(filename, 'r')
                 
        result=f.readlines()[3:]
        try:
            (node, benchmark, th) = filename.split('/')[-1].replace('.dat','').split('-')   
        except:
            (node, benchmark, th, ref) = filename.split('/')[-1].replace('.dat','').split('-')          
        th = int(th)
        if th not in [10,11]:
            size=[]
            mflops=[]    
            for r in result:     
                if "N=" in r or '/' in r:
                    stop=True
                if not stop:
                    size.append(int(r.strip().split(' ')[0]))
                    mflops.append(float(r.strip().split(' ')[-1]))
                
            d_all[node][benchmark][th]['size']=size
            d_all[node][benchmark][th]['mflops']=mflops
 
            
    return d_all                           
 ########################################################################################
          
hpx_dir_ref='/home/shahrzad/repos/Blazemark/data/matrix/06-13-2019/reference_hpx/marvin/master/'         
d_hpx_ref=create_dict(hpx_dir_ref)      
hpx_dir='/home/shahrzad/repos/Blazemark/data/matrix/06-13-2019/marvin/'         
hpx_dir1='/home/shahrzad/repos/Blazemark/data/matrix/09-15-2019/'         
hpx_dir2='/home/shahrzad/repos/Blazemark/data/matrix/06-13-2019/trillian/'
hpx_dir3='/home/shahrzad/repos/Blazemark/results/new_threads/'
(d_hpx,  chunk_sizes, block_sizes, thr, benchmarks, mat_sizes)=create_dict_relative_norepeat([hpx_dir,hpx_dir1,hpx_dir2])                 
hpxmp_dir='/home/shahrzad/repos/Blazemark/data/hpxmp/CCGRID20-Nov/'
d_hpxmp=create_dict_reference(hpxmp_dir,'hpx')                 
d_openmp=create_dict_reference(hpxmp_dir)                 

openmp_dir='/home/shahrzad/repos/Blazemark/data/matrix/06-13-2019/openmp/'
(d_openmp,  chunk_sizes, block_sizes, thr, benchmarks, mat_sizes)=create_dict_relative_norepeat([openmp_dir])                 
         

d_openmp=create_dict_openmp(openmp_dir_1)

i=1
for benchmark in benchmarks:
    for th in thr:
        plt.figure(i)
        for a in ['4']:        
            for b in d_hpx[node][benchmark][th].keys():# block_sizes:
                if b.startswith(a+'-'):
                    for c in d_hpx[node][benchmark][th][b].keys():#chunk_sizes:   
                        
                        if d_hpx[node][benchmark][th][b][c]['mflops'].count(0)<0.5*len(d_hpx[node][benchmark][th][b][c]['mflops']):
                            plt.plot(d_hpx[node][benchmark][th][b][c]['size'], d_hpx[node][benchmark][th][b][c]['mflops'],label='chunk_size: '+str(c)+' block_size: '+str(b)+ '  '+str(th)+' threads',marker='*')
    #                        plt.plot(d_openmp[benchmark][th]['size'], d_openmp[benchmark][th]['mflops'],label='openmp '+str(th)+' threads')
    
                            plt.xlabel("# matrix size")           
                            plt.ylabel('MFlops')
                            plt.xscale('log')
                            plt.grid(True, 'both')
                            plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
                            plt.title('hpx   '+benchmark)
                        i=i+1    
                        plt.figure(i)
#                            plt.savefig(pp, format='pdf',bbox_inches='tight')
                        print('')        
#plt.show()
#pp.close()                   


#f=open('/home/shahrzad/repos/Blazemark/data/data.csv','w')
#f_writer=csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
#f_writer.writerow(['benchmark','matrix_size','num_threads','block_size_row','block_size_col','chunk_size','num_blocks','mflops'])
#for benchmark in d_hpx.keys():
#    for th in d_hpx[benchmark].keys():
#        for block_size in d_hpx[benchmark][th].keys():
#            for chunk_size in d_hpx[benchmark][th][block_size].keys():
#                if len(d_hpx[benchmark][th][block_size][chunk_size])!=0:
#                    for j in range(len(d_hpx[benchmark][th][block_size][chunk_size]['size'])):
#                        m=d_hpx[benchmark][th][block_size][chunk_size]['size'][j]
#                        b_r=int(b.split('-')[0])
#                        b_c=int(b.split('-')[1])
#                        rest1=b_r%simdsize
#                        rest2=b_c%simdsize
#                        if b_r>m:
#                            b_r=m
#                        if b_c>m:
#                            b_c=m
#                        if b_c%simdsize!=0:
#                                    b_c=b_c+simdsize-b_c%simdsize
#                        equalshare1=math.ceil(m/b_r)
#                        equalshare2=math.ceil(m/b_c)  
#                        for i in range(len(d_hpx[benchmark][th][block_size][chunk_size]['size'])):
#                            f_writer.writerow([benchmark,str(m),str(th),str(b_r), str(b_c),str(chunk_size),str(equalshare1*equalshare2), str(d_hpx[benchmark][th][block_size][chunk_size]['mflops'][i])])
#f.close()                    
#  
(d_hpx_old,  chunk_sizes, block_sizes, thr, benchmarks, mat_sizes_2)=create_dict('/home/shahrzad/repos/Blazemark/results/previous')                 
(d_hpx,  chunk_sizes, block_sizes, thr, benchmarks, mat_sizes)=create_dict(hpx_dir)   
hpx_dir='/home/shahrzad/repos/Blazemark/data/matrix/06-13-2019/marvin'              
(d_hpx,  chunk_sizes, block_sizes, thr, benchmarks, mat_sizes)=create_dict_relative(hpx_dir)    
papi_directory='/home/shahrzad/repos/Blazemark/data/matrix/08-07-2019/performance_counters/'

(d_hpx,  chunk_sizes, block_sizes, thr, benchmarks, mat_sizes)=create_dict_relative_norepeat_counters_onebyone(papi_directory)                 

perf_directory='/home/shahrzad/repos/Blazemark/data/performance_plots/matrix/08-07-2019/performance_counters'

###########################################################################
#performnce counters plots
#############################################################################
i=1
th=4
m=912
benchmark='dmatdmatadd'
node='marvin'



#plot number of cache misses based on chunk size for a matrix size
for benchmark in benchmarks:
    for th in d_hpx[node][benchmark].keys():
#        pp = PdfPages(perf_directory+'/bath_tub_'+benchmark+'_different_matrix_sizes_'+str(th)+'.pdf')

        for m in mat_sizes[benchmark]: 
            plt.figure(i)
            for b in d_hpx[node][benchmark][th].keys():
                results=[]
                l2_cm=[]
                l2_ch=[]
                l2_miss_rate=[]
                chunk_sizes=[]
                grain_sizes=[]
                for c in d_hpx[node][benchmark][th][b].keys():                    
                    k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                    if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                        b_r=int(b.split('-')[0])
                        b_c=int(b.split('-')[1])
                        rest1=b_r%simdsize
                        rest2=b_c%simdsize
                        if b_r>m:
                            b_r=m
                        if b_c>m:
                            b_c=m
                        if b_c%simdsize!=0:
                            b_c=b_c+simdsize-b_c%simdsize
                        equalshare1=math.ceil(m/b_r)
                        equalshare2=math.ceil(m/b_c)  
                        chunk_sizes.append(c)
                        num_blocks=equalshare1*equalshare2
                        num_elements_uncomplete=0
                        if b_c<m:
                            num_elements_uncomplete=(m%b_c)*b_r
                        mflop=0
                        if benchmark=='dmatdmatadd':                            
                            mflop=b_r*b_c                            
                        elif benchmark=='dmatdmatdmatadd':
                            mflop=b_r*b_c*2
                        else:
                            mflop=b_r*b_c*(2*m)
                        num_elements=[mflop]*num_blocks
                        if num_elements_uncomplete:
                            for j in range(1,equalshare1+1):
                                num_elements[j*equalshare2-1]=num_elements_uncomplete
                        data_type=8
                        grain_size=sum(num_elements[0:c])
                        num_mat=3
                        if benchmark=='dmatdmatdmatadd':
                            num_mat=4
                        cost=c*mflop*num_mat/data_type
                        grain_sizes.append(grain_size)
                        results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k])
                        l2_cm.append(d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'])
                        l2_ch.append([d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][l]-d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][l] for l in range(th)])
                        l2_miss_rate.append([d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][j]/d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][j] for j in range(th)])

                if len(chunk_sizes)!=0:      
                    t0=[l[0] for l in l2_miss_rate]
                    t1=[l[1] for l in l2_miss_rate]
                    t2=[l[2] for l in l2_miss_rate]
                    t3=[l[3] for l in l2_miss_rate]
                    plt.figure(i)
                    plt.plot(chunk_sizes, t0, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b_r)+'-'+str(b_c)+'  num_blocks:'+str(equalshare1*equalshare2)+' block size '+str(b)+' core 0')
                    plt.ylabel('l2_cache_misse rate')
                    plt.xscale('log')
                    plt.title(benchmark)
                    plt.grid(True, 'both')
                    plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
                    plt.figure(i+1)

                    plt.plot(chunk_sizes, t1, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b)+'  num_blocks:'+str(equalshare1*equalshare2)+' block size '+str(b_r)+'-'+str(b_c)+' core 1')
                    plt.ylabel('l2_cache_misse rate')
                    plt.xscale('log')
                    plt.title(benchmark)
                    plt.grid(True, 'both')
                    plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
                    plt.figure(i+2)

                    plt.plot(chunk_sizes, t2, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b)+'  num_blocks:'+str(equalshare1*equalshare2)+' block size '+str(b_r)+'-'+str(b_c)+' core 2')
                    plt.ylabel('l2_cache_misse rate')
                    plt.xscale('log')
                    plt.title(benchmark)
                    plt.grid(True, 'both')
                    plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
                    plt.figure(i+3)

                    plt.plot(chunk_sizes, t3, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b)+'  num_blocks:'+str(equalshare1*equalshare2)+' block size '+str(b_r)+'-'+str(b_c)+' core 3')
                    plt.ylabel('l2_cache_misse rate')
                    plt.xscale('log')
                    plt.title(benchmark)
                    plt.grid(True, 'both')
                    plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
                    
#                    t0=[l[0] for l in l2_ch]
#                    t1=[l[1] for l in l2_ch]
#                    t2=[l[2] for l in l2_ch]
#                    t3=[l[3] for l in l2_ch]
#
#                    plt.plot(chunk_sizes, t0, label='0')
#                    plt.plot(chunk_sizes, t1, label='1')
#                    plt.plot(chunk_sizes, t2, label='2')
#                    plt.plot(chunk_sizes, t3, label='3')
#                    plt.ylabel('number of cache_hits')
#                    plt.xscale('log')
#                    plt.title(benchmark)
#                    plt.grid(True, 'both')
#                    plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
                    
#                    plt.plot(chunk_sizes, results, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b)+'  num_blocks:'+str(equalshare1*equalshare2))
#                    plt.plot(grain_sizes, results, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b_r)+'-'+str(b_c)+'  num_blocks:'+str(equalshare1*equalshare2))
#                    plt.xlabel("grain_size(flop)")           
#
##                    plt.xlabel("chunk_size")           
#                    plt.ylabel('MFlops')
#                    plt.xscale('log')
#                    plt.title(benchmark)
#                    plt.grid(True, 'both')
#                    plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
            print('')     
            plt.savefig(pp, format='pdf',bbox_inches='tight')
            i=i+1

#plot number of cache misses based on chunk size for a matrix size
for benchmark in benchmarks:
#        pp = PdfPages(perf_directory+'/bath_tub_'+benchmark+'_different_matrix_sizes_'+str(th)+'.pdf')

    for m in mat_sizes[benchmark]: 
        for th in d_hpx[node][benchmark].keys():

            plt.figure(i)
            results=[]
            l2_cm=[]
            l2_ch=[]
            l2_miss_rate=[]
            chunk_sizes=[]
            grain_sizes=[]
            block_sizes=[]
            for b in d_hpx[node][benchmark][th].keys():            
                for c in d_hpx[node][benchmark][th][b].keys():                    
                    k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                    if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                        b_r=int(b.split('-')[0])
                        b_c=int(b.split('-')[1])
                        rest1=b_r%simdsize
                        rest2=b_c%simdsize
                        if b_r>m:
                            b_r=m
                        if b_c>m:
                            b_c=m
                        if b_c%simdsize!=0:
                            b_c=b_c+simdsize-b_c%simdsize
                        equalshare1=math.ceil(m/b_r)
                        equalshare2=math.ceil(m/b_c)  
                        chunk_sizes.append(c)
                        num_blocks=equalshare1*equalshare2
                        num_elements_uncomplete=0
                        if b_c<m:
                            num_elements_uncomplete=(m%b_c)*b_r
                        mflop=0
                        if benchmark=='dmatdmatadd':                            
                            mflop=b_r*b_c                            
                        elif benchmark=='dmatdmatdmatadd':
                            mflop=b_r*b_c*2
                        else:
                            mflop=b_r*b_c*(2*m)
                        num_elements=[mflop]*num_blocks
                        if num_elements_uncomplete:
                            for j in range(1,equalshare1+1):
                                num_elements[j*equalshare2-1]=num_elements_uncomplete
                        data_type=8
                        grain_size=sum(num_elements[0:c])
                        num_mat=3
                        if benchmark=='dmatdmatdmatadd':
                            num_mat=4
                        cost=c*mflop*num_mat/data_type
                        grain_sizes.append(grain_size)
                        results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k])
                        l2_cm.append(d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'])
                        l2_ch.append([d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][l]-d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][l] for l in range(int(th))])
                        l2_miss_rate.append([d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][j]/d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][j] for j in range(int(th))])
                        block_sizes.append(b)
            t0=[l[0] for l in l2_miss_rate]
            t1=[l[1] for l in l2_miss_rate]
            t2=[l[2] for l in l2_miss_rate]
            t3=[l[3] for l in l2_miss_rate]
            plt.figure(i)
            plt.axes([0, 0, 2, 1])
            plt.scatter(grain_sizes, t0, label=str(th)+' threads  matrix_size:'+str(m)+' core 0')
            plt.ylabel('l2_cache_misse rate')
            plt.xlabel('Grain size')
            plt.xscale('log')
            plt.title(benchmark)
            plt.grid(True, 'both')
            plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
            plt.figure(i+1)

            plt.plot(chunk_sizes, t1, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b)+'  num_blocks:'+str(equalshare1*equalshare2)+' block size '+str(b_r)+'-'+str(b_c)+' core 1')
            plt.ylabel('l2_cache_misse rate')
            plt.xscale('log')
            plt.title(benchmark)
            plt.grid(True, 'both')
            plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
            plt.figure(i+2)

            plt.plot(chunk_sizes, t2, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b)+'  num_blocks:'+str(equalshare1*equalshare2)+' block size '+str(b_r)+'-'+str(b_c)+' core 2')
            plt.ylabel('l2_cache_misse rate')
            plt.xscale('log')
            plt.title(benchmark)
            plt.grid(True, 'both')
            plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
            plt.figure(i+3)

            plt.plot(chunk_sizes, t3, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b)+'  num_blocks:'+str(equalshare1*equalshare2)+' block size '+str(b_r)+'-'+str(b_c)+' core 3')
            plt.ylabel('l2_cache_misse rate')
            plt.xscale('log')
            plt.title(benchmark)
            plt.grid(True, 'both')
            plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)

            print('')     
            plt.savefig(pp, format='pdf',bbox_inches='tight')
            i=i+1

#plot number of cache misses based on chunk size/grain size for a matrix size
for benchmark in benchmarks:

    for m in mat_sizes[benchmark]: 
        pp = PdfPages(perf_directory+'/cache_miss_'+node+'_'+benchmark+'_'+str(int(m))+'.pdf')

        for th in d_hpx[node][benchmark].keys():
            results=[]
            l2_cm=[]
            l2_ch=[]
            l2_miss_rate=[]
            chunk_sizes=[]
            grain_sizes=[]
            block_sizes=[]
            for b in d_hpx[node][benchmark][th].keys():            
                for c in d_hpx[node][benchmark][th][b].keys():                    
                    k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                    if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                        b_r=int(b.split('-')[0])
                        b_c=int(b.split('-')[1])
                        rest1=b_r%simdsize
                        rest2=b_c%simdsize
                        if b_r>m:
                            b_r=m
                        if b_c>m:
                            b_c=m
                        if b_c%simdsize!=0:
                            b_c=b_c+simdsize-b_c%simdsize
                        equalshare1=math.ceil(m/b_r)
                        equalshare2=math.ceil(m/b_c)  
                        chunk_sizes.append(c)
                        num_blocks=equalshare1*equalshare2
                        num_elements_uncomplete=0
                        if b_c<m:
                            num_elements_uncomplete=(m%b_c)*b_r
                        mflop=0
                        if benchmark=='dmatdmatadd':                            
                            mflop=b_r*b_c                            
                        elif benchmark=='dmatdmatdmatadd':
                            mflop=b_r*b_c*2
                        else:
                            mflop=b_r*b_c*(2*m)
                        num_elements=[mflop]*num_blocks
                        if num_elements_uncomplete:
                            for j in range(1,equalshare1+1):
                                num_elements[j*equalshare2-1]=num_elements_uncomplete
                        data_type=8
                        grain_size=sum(num_elements[0:c])
                        num_mat=3
                        if benchmark=='dmatdmatdmatadd':
                            num_mat=4
                        cost=c*mflop*num_mat/data_type
                        grain_sizes.append(grain_size)
                        results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k])
                        l2_cm.append(d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'])
                        l2_ch.append([d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][l]-d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][l] for l in range(int(th))])
                        l2_miss_rate.append([d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][j]/d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][j] for j in range(int(th))])
                        block_sizes.append(b)
#            t0=[l[0] for l in l2_miss_rate]
#            t1=[l[1] for l in l2_miss_rate]
#            t2=[l[2] for l in l2_miss_rate]
#            t3=[l[3] for l in l2_miss_rate]
            plt.figure(i)
#            plt.axes([0, 0, 2, 1])
#            plt.scatter(grain_sizes, t0, label=str(th)+' threads  matrix_size:'+str(m)+' core 0')           
#            plt.ylabel('l2_cache_misse rate')
#            plt.xlabel('Grain size')
#            plt.xscale('log')
#            plt.title(benchmark)
#            plt.grid(True, 'both')
#            plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
#            plt.figure(i+1)
            
            plt.axes([0, 0, 2, 1])
            avg_l2=[sum(l)/th for l in l2_miss_rate]
            plt.scatter(grain_sizes, [sum(l)/th for l in l2_miss_rate], label=str(th)+' threads  matrix_size:'+str(m)+' core 0')
            plt.ylabel('average l2_cache_misse rate')
            plt.xlabel('Grain size')
            plt.xscale('log')
            plt.title(benchmark)
            plt.grid(True, 'both')
            for e in range(len(l2_miss_rate)):
                plt.annotate(block_sizes[e], # this is the text
                                         (grain_sizes[e],avg_l2[e]), # this is the point to label
                                         textcoords="offset points", # how to position the text
                                         xytext=(0,10), # distance from text to points (x,y)
                                         ha='center') # horizontal alignment can be left, right or center
                                    
            plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
            plt.savefig(pp, format='pdf',bbox_inches='tight')
            i=i+1
            
        plt.show()
        pp.close()
        
            plt.figure(i+1)

            plt.plot(chunk_sizes, t1, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b)+'  num_blocks:'+str(equalshare1*equalshare2)+' block size '+str(b_r)+'-'+str(b_c)+' core 1')
            plt.ylabel('l2_cache_misse rate')
            plt.xscale('log')
            plt.title(benchmark)
            plt.grid(True, 'both')
            plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
            plt.figure(i+2)

            plt.plot(chunk_sizes, t2, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b)+'  num_blocks:'+str(equalshare1*equalshare2)+' block size '+str(b_r)+'-'+str(b_c)+' core 2')
            plt.ylabel('l2_cache_misse rate')
            plt.xscale('log')
            plt.title(benchmark)
            plt.grid(True, 'both')
            plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
            plt.figure(i+3)

            plt.plot(chunk_sizes, t3, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b)+'  num_blocks:'+str(equalshare1*equalshare2)+' block size '+str(b_r)+'-'+str(b_c)+' core 3')
            plt.ylabel('l2_cache_misse rate')
            plt.xscale('log')
            plt.title(benchmark)
            plt.grid(True, 'both')
            plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)

            print('')     
            plt.savefig(pp, format='pdf',bbox_inches='tight')
            i=i+1
###################################################################
#plot idle rate based on grain size for a matrix size
for benchmark in benchmarks:
#        pp = PdfPages(perf_directory+'/bath_tub_'+benchmark+'_different_matrix_sizes_'+str(th)+'.pdf')

    for m in mat_sizes[benchmark]: 
        pp = PdfPages(perf_directory+'/idle_rate_'+node+'_'+benchmark+'_'+str(int(m))+'.pdf')

        for th in d_hpx[node][benchmark].keys():

            plt.figure(i)
            results=[]
            idle_rates=[]
            chunk_sizes=[]
            grain_sizes=[]
            block_sizes=[]
            for b in d_hpx[node][benchmark][th].keys():            
                for c in d_hpx[node][benchmark][th][b].keys():                    
                    k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                    if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                        b_r=int(b.split('-')[0])
                        b_c=int(b.split('-')[1])
                        rest1=b_r%simdsize
                        rest2=b_c%simdsize
                        if b_r>m:
                            b_r=m
                        if b_c>m:
                            b_c=m
                        if b_c%simdsize!=0:
                            b_c=b_c+simdsize-b_c%simdsize
                        equalshare1=math.ceil(m/b_r)
                        equalshare2=math.ceil(m/b_c)  
                        chunk_sizes.append(c)
                        num_blocks=equalshare1*equalshare2
                        num_elements_uncomplete=0
                        if b_c<m:
                            num_elements_uncomplete=(m%b_c)*b_r
                        mflop=0
                        if benchmark=='dmatdmatadd':                            
                            mflop=b_r*b_c                            
                        elif benchmark=='dmatdmatdmatadd':
                            mflop=b_r*b_c*2
                        else:
                            mflop=b_r*b_c*(2*m)
                        num_elements=[mflop]*num_blocks
                        if num_elements_uncomplete:
                            for j in range(1,equalshare1+1):
                                num_elements[j*equalshare2-1]=num_elements_uncomplete
                        data_type=8
                        grain_size=sum(num_elements[0:c])
                        num_mat=3
                        if benchmark=='dmatdmatdmatadd':
                            num_mat=4
                        cost=c*mflop*num_mat/data_type
                        grain_sizes.append(grain_size)
                        results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k])
                        idle_rates.append(d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['idle_rate'])
                        block_sizes.append(b)
            
            i0=[sum(idl)/th for idl in idle_rates]
            plt.axes([0, 0, 2, 1])
            plt.scatter(grain_sizes, i0, label=str(th)+' threads  matrix_size:'+str(m)+' core 0')
            plt.ylabel('idle rate')
            plt.xlabel('Grain size')
            plt.xscale('log')
            plt.title(benchmark)
            plt.grid(True, 'both')
            for e in range(len(idle_rates)):
                plt.annotate(block_sizes[i], # this is the text
                                         (grain_sizes[e],i0[e]), # this is the point to label
                                         textcoords="offset points", # how to position the text
                                         xytext=(0,3), # distance from text to points (x,y)
                                         ha='center') # horizontal alignment can be left, right or center
                                    
            plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
            plt.savefig(pp, format='pdf',bbox_inches='tight')
            i=i+1
            
        plt.show()
        pp.close()



(d_hpx,  chunk_sizes, block_sizes, thr, benchmarks, mat_sizes)=create_dict_relative_norepeat_counters_onebyone(papi_directory)                 
perf_directory='/home/shahrzad/repos/Blazemark/data/performance_plots/matrix/08-07-2019/performance_counters'
################################################################
#3d plot
################################################################
fig = plt.figure()
ax = plt.axes(projection='3d')
# Data for a three-dimensional line
zline = np.linspace(0, 15, 1000)
xline = np.sin(zline)
yline = np.cos(zline)
ax.plot3D(xline, yline, zline, 'gray')

# Data for three-dimensional scattered points
zdata = 15 * np.random.random(100)
xdata = np.sin(zdata) + 0.1 * np.random.randn(100)
ydata = np.cos(zdata) + 0.1 * np.random.randn(100)
ax.scatter3D(grain_sizes, block_sizes, results, c=results, cmap='Greens');





animation=0
#mflops based on block size and grain size
for node in ['marvin', 'trillian']:
    for benchmark in benchmarks:
        pp = PdfPages(perf_directory+'/3d_plot_'+benchmark+'_'+node+'.pdf')

        for m in mat_sizes[benchmark]: 
            for th in d_hpx[node][benchmark].keys():
                results=[]
                l2_cm=[]
                l2_ch=[]
                l2_miss_rate=[]
                avg_l2_miss_rate=[]
                chunk_sizes=[]
                real_block_sizes=[]
                block_sizes=[]
                grain_sizes=[]
                bl=1
                for b in d_hpx[node][benchmark][th].keys():
                    for c in d_hpx[node][benchmark][th][b].keys():                    
                        k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                        if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                            b_r=int(b.split('-')[0])
                            b_c=int(b.split('-')[1])
                            rest1=b_r%simdsize
                            rest2=b_c%simdsize
                            if b_r>m:
                                b_r=m
                            if b_c>m:
                                b_c=m
                            if b_c%simdsize!=0:
                                b_c=b_c+simdsize-b_c%simdsize
                            equalshare1=math.ceil(m/b_r)
                            equalshare2=math.ceil(m/b_c)  
                            num_blocks=equalshare1*equalshare2
                            num_elements_uncomplete=0
                            if b_c<m:
                                num_elements_uncomplete=(m%b_c)*b_r
                            mflop=0
                            if benchmark=='dmatdmatadd':                            
                                mflop=b_r*b_c                            
                            elif benchmark=='dmatdmatdmatadd':
                                mflop=b_r*b_c*2
                            else:
                                mflop=b_r*b_c*(2*m)
                            num_elements=[mflop]*num_blocks
                            if num_elements_uncomplete:
                                for j in range(1,equalshare1+1):
                                    num_elements[j*equalshare2-1]=num_elements_uncomplete
                            data_type=8
                            grain_size=sum(num_elements[0:c])
                            num_mat=3
                            if benchmark=='dmatdmatdmatadd':
                                num_mat=4
                            cost=c*mflop*num_mat/data_type
                            grain_sizes.append(grain_size)
                            chunk_sizes.append(c)
                            block_sizes.append(bl)  
                            
                            if b not in real_block_sizes:
                                real_block_sizes.append(b)
    
                            
        #                    block_sizes.append(str(b_r)+'-'+str(b_c))
                            results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k])
                            l2_cm.append(d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'])
                            l2_ch.append([d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][l]-d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][l] for l in range(th)])
                            ind_miss=[d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][j]/d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][j] for j in range(th)]
                            l2_miss_rate.append(ind_miss)
                            avg_l2_miss_rate.append(sum(ind_miss)/th)
                    bl=bl+1
                
                y=block_sizes
                x=grain_sizes
                z=results
                if not animation:
                    fig = plt.figure(i)
    
                    ax = fig.add_subplot(1,1,1, projection='3d')
                    triang = mtri.Triangulation(x, y)
                    
                    ax.plot_trisurf(triang, z, cmap='jet')
                    ax.scatter(x,y,z, marker='.', s=10, c="black", alpha=0.5)
                    ax.view_init(elev=10, azim=-110)
                    ax.set_xlabel('Grain size')
                    ax.set_ylabel('Block size')
                    ax.set_zlabel('Mflops')
                    plt.title(benchmark+'   matrix size:'+str(m)+'    '+str(th)+' threads')
                    plt.savefig(pp, format='pdf',bbox_inches='tight')
                    print('')
                    i=i+1
                else:                    
#                    surf=ax.plot_trisurf(y, x, z, cmap=plt.cm.viridis, linewidth=0.2)
#                    fig.colorbar( surf, shrink=0.5, aspect=5)
#                    ax.view_init(10, 60)
#                    plt.show()
                    
                    for angle in range(0,360,10):
                        fig = plt.figure(i)
                        ax = fig.gca(projection='3d')
    
                        triang = mtri.Triangulation(x, y)
                        
                        ax.plot_trisurf(triang, z, cmap='jet')
                        ax.scatter(x,y,z, marker='.', s=10, c="black", alpha=0.5)
                        ax.view_init(elev=10, azim=angle)
                        ax.set_xlabel('Grain size')
                        ax.set_ylabel('Block size')
                        ax.set_zlabel('Mflops')
                        plt.title(benchmark+'   matrix size:'+str(m)+'    '+str(th)+' threads')
                        filename='/home/shahrzad/repos/Blazemark/results/step_'+str(angle)+'.png'
                        plt.savefig(filename, dpi=96)
                        plt.gca()
        if not animation:
            plt.show()
            pp.close()     
            
animation=0

#mflops based on num_threads and grain size
for node in ['marvin', 'trillian']:
    for benchmark in benchmarks:
#        pp = PdfPages(perf_directory+'/3d_plot_'+benchmark+'_'+node+'.pdf')
        for m in mat_sizes[benchmark]: 
            threads=[]
            results=[]
            chunk_sizes=[]
            real_block_sizes=[]
            block_sizes=[]
            grain_sizes=[]
            for th in range(1,9): #d_hpx[node][benchmark].keys():

                bl=1
                for b in d_hpx[node][benchmark][th].keys():
                    for c in d_hpx[node][benchmark][th][b].keys():                    
                        k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                        if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                            b_r=int(b.split('-')[0])
                            b_c=int(b.split('-')[1])
                            rest1=b_r%simdsize
                            rest2=b_c%simdsize
                            if b_r>m:
                                b_r=m
                            if b_c>m:
                                b_c=m
                            if b_c%simdsize!=0:
                                b_c=b_c+simdsize-b_c%simdsize
                            equalshare1=math.ceil(m/b_r)
                            equalshare2=math.ceil(m/b_c)  
                            num_blocks=equalshare1*equalshare2
                            num_elements_uncomplete=0
                            if b_c<m:
                                num_elements_uncomplete=(m%b_c)*b_r
                            mflop=0
                            if benchmark=='dmatdmatadd':                            
                                mflop=b_r*b_c                            
                            elif benchmark=='dmatdmatdmatadd':
                                mflop=b_r*b_c*2
                            else:
                                mflop=b_r*b_c*(2*m)
                            num_elements=[mflop]*num_blocks
                            if num_elements_uncomplete:
                                for j in range(1,equalshare1+1):
                                    num_elements[j*equalshare2-1]=num_elements_uncomplete
                            data_type=8
                            grain_size=sum(num_elements[0:c])
                            num_mat=3
                            if benchmark=='dmatdmatdmatadd':
                                num_mat=4
                            cost=c*mflop*num_mat/data_type
                            grain_sizes.append(grain_size)
                            chunk_sizes.append(c)
                            block_sizes.append(bl)  
                            threads.append(th)

                            if b not in real_block_sizes:
                                real_block_sizes.append(b)
    
        #                    block_sizes.append(str(b_r)+'-'+str(b_c))
                            results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k])                            
                    bl=bl+1
                
            y=threads
            x=grain_sizes
            z=results
            if not animation:
                fig = plt.figure(i)

                ax = fig.add_subplot(1,1,1, projection='3d')
                triang = mtri.Triangulation(x, y)
                ax.plot_trisurf(triang, z, cmap='jet')
                ax.scatter(x,y,z, marker='.', s=10, c="black", alpha=0.5)
                ax.view_init(elev=10, azim=-110)
                ax.set_xlabel('Grain size')
#                ax.set_xticks(10**np.arange(1,7))
#                ax.set_xticklabels(10**np.arange(1,7))
                ax.set_ylabel('#cores')
                ax.zaxis.set_rotate_label(False)
                ax.set_zlabel('Mflops',rotation=90)
                ax.get_proj = lambda: np.dot(Axes3D.get_proj(ax), np.diag([1.18, 1.1, 1, 1]))
#                plt.title(node+'  '+benchmark.upper()+'   matrix size:'+str(int(m))+'x'+str(int(m)))
                plt.savefig('/home/shahrzad/src/Dissertation/images/fig2.png', dpi=300)
                print('')
                i=i+1
            else:                    
#                    surf=ax.plot_trisurf(y, x, z, cmap=plt.cm.viridis, linewidth=0.2)
#                    fig.colorbar( surf, shrink=0.5, aspect=5)
#                    ax.view_init(10, 60)
#                    plt.show()
                
                for angle in range(0,360,10):
                    fig = plt.figure(i)
                    ax = fig.gca(projection='3d')

                    triang = mtri.Triangulation(x, y)
                    
                    ax.plot_trisurf(triang, z, cmap='jet')
                    ax.scatter(x,y,z, marker='.', s=10, c="black", alpha=0.5)
                    ax.view_init(elev=10, azim=angle)
                    ax.set_xlabel('Grain size')
                    ax.set_ylabel('#cores')
                    ax.set_zlabel('Mflops',rotation=90)
                    ax.zaxis.set_rotate_label(False)
#                    ax.set_yticks(d_hpx[node][benchmark].keys())
#                    ax.set_xticklabels(d_hpx[node][benchmark].keys())
                    ax.get_proj = lambda: np.dot(Axes3D.get_proj(ax), np.diag([1.18, 1.1, 1, 1]))

#                    plt.title(node+'  '+benchmark+'   matrix size:'+str(m))
                    filename='/home/shahrzad/repos/Blazemark/results/3d/'+node+'_'+benchmark+'_'+str(m)+'_step_'+str(angle)+'.png'
                    plt.savefig(filename, dpi=300)
                    plt.gca()
        if not animation:
            plt.show()
            pp.close()                 


#plot all data mflops based on grain_size and num_threads    
for node in ['marvin', 'trillian']:
    for benchmark in benchmarks:
#        pp = PdfPages(perf_directory+'/3d_plot_'+benchmark+'_'+node+'.pdf')
        threads=[]
        results=[]
        grain_sizes=[]
        m_sizes=[]
        for m in mat_sizes[benchmark]: 
            chunk_sizes=[]
            real_block_sizes=[]
            block_sizes=[]
            for th in range(1,9):#d_hpx[node][benchmark].keys():

                bl=1
                for b in d_hpx[node][benchmark][th].keys():
                    for c in d_hpx[node][benchmark][th][b].keys():                    
                        k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                        if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                            b_r=int(b.split('-')[0])
                            b_c=int(b.split('-')[1])
                            rest1=b_r%simdsize
                            rest2=b_c%simdsize
                            if b_r>m:
                                b_r=m
                            if b_c>m:
                                b_c=m
                            if b_c%simdsize!=0:
                                b_c=b_c+simdsize-b_c%simdsize
                            equalshare1=math.ceil(m/b_r)
                            equalshare2=math.ceil(m/b_c)  
                            num_blocks=equalshare1*equalshare2
                            num_elements_uncomplete=0
                            if b_c<m:
                                num_elements_uncomplete=(m%b_c)*b_r
                            mflop=0
                            if benchmark=='dmatdmatadd':                            
                                mflop=b_r*b_c                            
                            elif benchmark=='dmatdmatdmatadd':
                                mflop=b_r*b_c*2
                            else:
                                mflop=b_r*b_c*(2*m)
                            num_elements=[mflop]*num_blocks
                            if num_elements_uncomplete:
                                for j in range(1,equalshare1+1):
                                    num_elements[j*equalshare2-1]=num_elements_uncomplete
                            data_type=8
                            grain_size=sum(num_elements[0:c])
                            num_mat=3
                            if benchmark=='dmatdmatdmatadd':
                                num_mat=4
                            cost=c*mflop*num_mat/data_type
                            grain_sizes.append(np.log10(grain_size))
                            chunk_sizes.append(c)
                            block_sizes.append(bl)  
                            threads.append(th)
                            m_sizes.append(m)

                            if b not in real_block_sizes:
                                real_block_sizes.append(b)
    
        #                    block_sizes.append(str(b_r)+'-'+str(b_c))
                            results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k])                            
                    bl=bl+1
                
        y=threads
        x=grain_sizes
        z=results
        if not animation:
            NUM_COLORS = len(mat_sizes[benchmark])

            cm = plt.get_cmap('gist_rainbow')
            fig = plt.figure(i)

            ax = fig.add_subplot(1,1,1, projection='3d')
            triang = mtri.Triangulation(x, y)
            
            ax.plot_trisurf(triang, z, cmap='jet')
            n=np.array(m_sizes)
            n=(n-np.min(n))/(np.max(n)-np.min(n))
            ax.scatter(x,y,z, marker='.', s=10, c='black', alpha=0.5,cmap=cm)
            ax.view_init(elev=10, azim=170)
            ax.set_xlabel('Grain size')
            ax.set_ylabel('#cores')
            ax.set_zlabel('Mflops')
            plt.title(benchmark)
#                    plt.savefig(pp, format='pdf',bbox_inches='tight')
            print('')
            i=i+1
        else:                    
#                    surf=ax.plot_trisurf(y, x, z, cmap=plt.cm.viridis, linewidth=0.2)
#                    fig.colorbar( surf, shrink=0.5, aspect=5)
#                    ax.view_init(10, 60)
#                    plt.show()
            
            for angle in range(0,360,10):
                fig = plt.figure(i)
                ax = fig.gca(projection='3d')
                NUM_COLORS = len(mat_sizes[benchmark])

                triang = mtri.Triangulation(x, y)
                n=np.array(m_sizes)
                
#                ax.plot_trisurf(triang, z, cmap='jet')
                ax.scatter(x,y,z, marker='.', s=10, c=n,alpha=0.5,cmap=plt.get_cmap('rainbow'))
                ax.view_init(elev=10, azim=angle)
                ax.set_xlabel('Grain size')
                ax.set_ylabel('#cores')
                ax.set_zlabel('Mflops')
                ax.set_yticks(np.arange(1,9).tolist())
                ax.set_xticklabels(np.arange(1,9).tolist())
                ax.set_zlabel('Mflops',rotation=90)
                ax.zaxis.set_rotate_label(False)
#                plt.title(benchmark)
                filename='/home/shahrzad/repos/Blazemark/results/3d/'+'all_'+node+'_'+benchmark+'_step_'+str(angle)+'.png'
                plt.savefig(filename, dpi=300)
                plt.gca()
                

hpx_dir='/home/shahrzad/repos/Blazemark/data/matrix/06-13-2019/marvin/'         
hpx_dir1='/home/shahrzad/repos/Blazemark/data/matrix/09-15-2019/'         
hpx_dir2='/home/shahrzad/repos/Blazemark/data/matrix/06-13-2019/trillian/'
hpx_dir3='/home/shahrzad/repos/Blazemark/results/new_threads/'
hpx_dir4='/home/shahrzad/repos/Blazemark/data/matrix/06-13-2019/work_stealing_off'
hpx_dir5='/home/shahrzad/repos/Blazemark/data/matrix/c7/splittable/all_cores/spt_min_0'
hpx_dir6='/home/shahrzad/repos/Blazemark/data/matrix/c7/splittable/idle_cores/2'

(d_hpx,  chunk_sizes, block_sizes, thr, benchmarks, mat_sizes)=create_dict_relative_norepeat([hpx_dir5])                 

(d_hpx,  chunk_sizes, block_sizes, thr, benchmarks, mat_sizes)=create_dict_relative_norepeat([hpx_dir,hpx_dir1,hpx_dir2,hpx_dir5,hpx_dir6])                 
(d_hpx,  chunk_sizes, block_sizes, thr, benchmarks, mat_sizes)=create_dict_relative_norepeat([hpx_dir4])                 
            
simdsize=4
import math
import csv
f=open('/home/shahrzad/repos/Blazemark/data/data_perf_all.csv','w')
f_writer=csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
f_writer.writerow(['runtime','node','benchmark','matrix_size','num_threads','block_size_row','block_size_col','num_elements','work_per_core','w1','w2','w3','w4','w5','w6','w7','w8','chunk_size','grain_size','num_blocks','num_blocks/chunk_size','num_elements*chunk_size','num_blocks/num_threads','num_blocks/(chunk_size*(num_threads-1))','L1cache','L2cache','L3cache','cache_line','set_associativity','datatype','cost','simd_size','execution_time','num_tasks','mflops','include'])
node_type=0
for node in d_hpx.keys():
    if node=='marvin' or node=='marvin_old':
        L1cache='32768'
        L2cache='262144'
        L3cache='20971520'
        cache_line='8'
        set_associativity='512'
        simdsize=4
    elif node=='trillian':
        L1cache='65536'
        L2cache='2097152'
        L3cache='6291456'
        cache_line='16'
        simdsize=4
        set_associativity='131072'
    elif node=='medusa':
        L1cache='32768'
        L2cache='1048576'
        L3cache='28835840'
        cache_line='64'
        set_associativity='16' 
        simdsize=8
    benchmark_type=0
    for benchmark in d_hpx[node].keys():
        all_data=[]
        for th in [th for th in d_hpx[node][benchmark].keys() if th<=8]:
            for b in d_hpx[node][benchmark][th].keys():
                for c in d_hpx[node][benchmark][th][b].keys():  
                    for m in mat_sizes[benchmark]:
                        k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                        if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                            if not(benchmark=='dmatdmatadd' and (b=='64-64' or b=='8-1024' or b=='4-64')):  
                                r=d_hpx[node][benchmark][th][b][c]['mflops'][k]

                               
                                b_r=int(b.split('-')[0])
                                b_c=int(b.split('-')[1])
                                if b_r>m:
                                    b_r=m
                                if b_c>m:
                                    b_c=m
                                if b_c%simdsize!=0:
                                    b_c=b_c+simdsize-b_c%simdsize
                                
                                equalshare1=math.ceil(m/b_r)
                                equalshare2=math.ceil(m/b_c)  
                                num_blocks=equalshare1*equalshare2
                                aligned_m=m
                                if m%simdsize!=0:
                                    aligned_m=m+simdsize-m%simdsize
                                    
                                if th==1:
                                    ratio=0
                                else:
                                    ratio=str(num_blocks/(c*(th-1)))
                                mflop=0
                                if benchmark=='dmatdmatadd':                            
                                    mflop=b_r*b_c                            
                                elif benchmark=='dmatdmatdmatadd':
                                    mflop=b_r*b_c*2
                                else:
                                    mflop=b_r*b_c*(2*m)
                                    
                                num_elements=[mflop]*num_blocks
                                if aligned_m%b_c!=0:
                                    for j in range(1,equalshare1+1):
                                        if benchmark=='dmatdmatadd':                            
                                            num_elements[j*equalshare2-1]=(aligned_m%b_c)*b_r                            
                                        elif benchmark=='dmatdmatdmatadd':
                                            num_elements[j*equalshare2-1]=(aligned_m%b_c)*b_r*2
                                        else:
                                            num_elements[j*equalshare2-1]=(aligned_m%b_c)*b_r*(2*m)
                                    
                                if m%b_r!=0:
                                    for j in range(1,equalshare2+1):
                                        if benchmark=='dmatdmatadd':                            
                                            num_elements[(equalshare1-1)*equalshare2+j-1]=(m%b_r)*b_c                            
                                        elif benchmark=='dmatdmatdmatadd':
                                            num_elements[(equalshare1-1)*equalshare2+j-1]=(m%b_r)*b_c*2
                                        else:
                                            num_elements[(equalshare1-1)*equalshare2+j-1]=(m%b_r)*b_c*(2*m)
                                                                                                           
                                if aligned_m%b_c!=0 and m%b_r!=0:
                                    if benchmark=='dmatdmatadd':                            
                                        num_elements[-1]=(m%b_r)*(aligned_m%b_c)                   
                                    elif benchmark=='dmatdmatdmatadd':
                                        num_elements[-1]=(m%b_r)*(aligned_m%b_c)*2
                                    else:
                                        num_elements[-1]=(m%b_r)*(aligned_m%b_c)*(2*m)
                                                                                
                                data_type=8
                                grain_size=sum(num_elements[0:c])
                                num_mat=3
                                if benchmark=='dmatdmatdmatadd':
                                    num_mat=4
                                cost=c*mflop*num_mat/data_type
                                aligned_m=m
                                if m%simdsize!=0:
                                    aligned_m=m+simdsize-m%simdsize
                                if benchmark=='dmatdmatadd':                            
                                    mflop=(aligned_m)*m                          
                                elif benchmark=='dmatdmatdmatadd':
                                    mflop=2*(aligned_m)*m
                                else:
                                    mflop=2*(aligned_m)**3        
                                exec_time=mflop/r
                                num_tasks=np.ceil(num_blocks/c)
                                task_sizes=[0.]*int(num_tasks)
                                wc=[0.]*8
                                for i in range(int(num_tasks)):
                                    task_sizes[i]=sum(num_elements[i*c:(i+1)*c])
                                for i in range(th):
                                    wc[i]=sum([task_sizes[j] for j in range(len(task_sizes)) if j%th==i])
                                work_per_core=max(wc)
                                
                                include=1
                                if num_mat*b_r*b_c*8>int(L2cache):
                                    include=0
                                f_writer.writerow(['hpx',node,benchmark,str(m),str(th),b.split('-')[0], 
                                                   b.split('-')[1], str(b_r * b_c), str(work_per_core),
                                                   str(wc[0]),str(wc[1]),str(wc[2]),str(wc[3]),
                                                   str(wc[4]),str(wc[5]),str(wc[6]),str(wc[7]),
                                                   str(c),str(grain_size),str(num_blocks), str(num_blocks/c),
                                                   str(b_r * b_c*c),str(num_blocks/th),ratio,L1cache,L2cache,L3cache,cache_line,set_associativity,str(data_type),str(cost),str(simdsize),str(exec_time),str(num_tasks),r,str(include)])
        benchmark_type+=1
    node_type+=1        
f.close()                    
 
openmp_dir='/home/shahrzad/repos/Blazemark/data/matrix/06-13-2019/openmp/'
(d_openmp,  chunk_sizes, block_sizes, thr, benchmarks, mat_sizes)=create_dict_relative_norepeat([openmp_dir])                 
         
     
simdsize=4
import math
import csv
f=open('/home/shahrzad/repos/Blazemark/data/data_perf_all.csv','a')
f_writer=csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
node_type=0
for node in d_openmp.keys():
    if node=='marvin':
        L1cache='32768'
        L2cache='262144'
        L3cache='20971520'
        cache_line='8'
        set_associativity='512'
        simdsize=4
    elif node=='trillian':
        L1cache='65536'
        L2cache='2097152'
        L3cache='6291456'
        cache_line='16'
        simdsize=4
        set_associativity='131072'
    elif node=='medusa':
        L1cache='32768'
        L2cache='1048576'
        L3cache='28835840'
        cache_line='64'
        set_associativity='16' 
        simdsize=8
    benchmark_type=0
    for benchmark in d_openmp[node].keys():
        all_data=[]
        for th in [th for th in d_hpx[node][benchmark].keys() if th<=8]:
            for b in d_openmp[node][benchmark][th].keys():
                for c in d_openmp[node][benchmark][th][b].keys():  
                    for m in mat_sizes[benchmark]:
                        k=d_openmp[node][benchmark][th][b][c]['size'].index(m)
                        if 'mflops' in d_openmp[node][benchmark][th][b][c].keys() and d_openmp[node][benchmark][th][b][c]['mflops'][k]:
                            if not(benchmark=='dmatdmatadd' and (b=='64-64' or b=='8-1024' or b=='4-64')):  
                                r=d_openmp[node][benchmark][th][b][c]['mflops'][k]

                                b_r=int(b.split('-')[0])
                                b_c=int(b.split('-')[1])
                                if b_r>m:
                                    b_r=m
                                if b_c>m:
                                    b_c=m
                                if b_c%simdsize!=0:
                                    b_c=b_c+simdsize-b_c%simdsize
                                
                                equalshare1=math.ceil(m/b_r)
                                equalshare2=math.ceil(m/b_c)  
                                num_blocks=equalshare1*equalshare2
                                aligned_m=m
                                if m%simdsize!=0:
                                    aligned_m=m+simdsize-m%simdsize
                                    
                                if th==1:
                                    ratio=0
                                else:
                                    ratio=str(num_blocks/(c*(th-1)))
                                mflop=0
                                if benchmark=='dmatdmatadd':                            
                                    mflop=b_r*b_c                            
                                elif benchmark=='dmatdmatdmatadd':
                                    mflop=b_r*b_c*2
                                else:
                                    mflop=b_r*b_c*(2*m)
                                    
                                num_elements=[mflop]*num_blocks
                                if aligned_m%b_c!=0:
                                    for j in range(1,equalshare1+1):
                                        if benchmark=='dmatdmatadd':                            
                                            num_elements[j*equalshare2-1]=(aligned_m%b_c)*b_r                            
                                        elif benchmark=='dmatdmatdmatadd':
                                            num_elements[j*equalshare2-1]=(aligned_m%b_c)*b_r*2
                                        else:
                                            num_elements[j*equalshare2-1]=(aligned_m%b_c)*b_r*(2*m)
                                    
                                if m%b_r!=0:
                                    for j in range(1,equalshare2+1):
                                        if benchmark=='dmatdmatadd':                            
                                            num_elements[(equalshare1-1)*equalshare2+j-1]=(m%b_r)*b_c                            
                                        elif benchmark=='dmatdmatdmatadd':
                                            num_elements[(equalshare1-1)*equalshare2+j-1]=(m%b_r)*b_c*2
                                        else:
                                            num_elements[(equalshare1-1)*equalshare2+j-1]=(m%b_r)*b_c*(2*m)
                                                                                                           
                                if aligned_m%b_c!=0 and m%b_r!=0:
                                    if benchmark=='dmatdmatadd':                            
                                        num_elements[-1]=(m%b_r)*(aligned_m%b_c)                   
                                    elif benchmark=='dmatdmatdmatadd':
                                        num_elements[-1]=(m%b_r)*(aligned_m%b_c)*2
                                    else:
                                        num_elements[-1]=(m%b_r)*(aligned_m%b_c)*(2*m)
                                                                                
                                data_type=8
                                grain_size=sum(num_elements[0:c])
                                
                                num_mat=3
                                if benchmark=='dmatdmatdmatadd':
                                    num_mat=4
                                cost=c*mflop*num_mat/data_type
                                
                                if benchmark=='dmatdmatadd':                            
                                    mflop=(aligned_m)*m                           
                                elif benchmark=='dmatdmatdmatadd':
                                    mflop=2*(aligned_m)*m
                                else:
                                    mflop=2*(aligned_m)**3                
                                exec_time=mflop/r
                                num_tasks=np.ceil(num_blocks/c)
                                task_sizes=[0.]*int(num_tasks)

                                wc=[0.]*8
                                for i in range(int(num_tasks)):
                                    task_sizes[i]=sum(num_elements[i*c:(i+1)*c])
                                for i in range(th):
                                    wc[i]=sum([task_sizes[j] for j in range(len(task_sizes)) if j%th==i])
                                work_per_core=max(wc)
                                f_writer.writerow(['openmp',node,benchmark,str(m),str(th),b.split('-')[0], 
                                                   b.split('-')[1], str(b_r * b_c), str(work_per_core),
                                                   str(wc[0]),str(wc[1]),str(wc[2]),str(wc[3]),
                                                   str(wc[4]),str(wc[5]),str(wc[6]),str(wc[7]),
                                                   str(c),
                                                   str(grain_size),str(num_blocks), str(num_blocks/c),
                                                   str(b_r * b_c*c),str(num_blocks/th),ratio,L1cache,L2cache,L3cache,cache_line,set_associativity,str(data_type),str(cost),str(simdsize),str(exec_time),str(num_tasks),r])
        benchmark_type+=1
    node_type+=1        
f.close()                    
 


f=open('/home/shahrzad/repos/Blazemark/data/data_perf_max.csv','a')
f_writer=csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
f_writer.writerow(['node','benchmark','matrix_size','num_threads','block_size_row','block_size_col','num_elements','num_elements_uncomplete','chunk_size','grain_size','num_blocks','num_blocks/chunk_size','num_elements*chunk_size','num_blocks/num_threads','num_blocks/(chunk_size*(num_threads-1))','L1cache','L2cache','L3cache','cache_line','set_associativity','datatype','cost','mflops'])
max_results={}   
min_max_grain_size={}
for node in d_hpx.keys():  
    min_max_grain_size[node]={}
    if node=='marvin':
        L1cache='32768'
        L2cache='262144'
        L3cache='20971520'
        cache_line='64'
        set_associativity='512'
    elif node=='trillian':
        L1cache='65536'
        L2cache='2097152'
        L3cache='6291456'
        cache_line='64'
        set_associativity='131072'
    max_results[node]={}
    for benchmark in d_hpx[node].keys(): 
        min_max_grain_size[node][benchmark]={}
        max_results[node][benchmark]={}
        for th in d_hpx[node][benchmark].keys():
            min_max_grain_size[node][benchmark][th]={}
            max_results[node][benchmark][th]={}
            for m in mat_sizes[benchmark]:
                min_max_grain_size[node][benchmark][th][m]={}
                min_grain=np.inf
                max_grain=0
                max_results[node][benchmark][th][m]=[] 
                results=[]
                chunk_sizes=[]
                bs=[]
                for b in d_hpx[node][benchmark][th].keys():
                    for c in d_hpx[node][benchmark][th][b]:                    
                        k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                        if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                            chunk_sizes.append(c)
                            results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k]) 
                            bs.append(b)
                if len(chunk_sizes)!=0:                
                    max_value=max(results)
                    
                    for r in results:                    
                        c=chunk_sizes[results.index(r)]
                        b=bs[results.index(r)]
                        max_results[node][benchmark][th][m].append((c,b,r))
                        b_r=int(b.split('-')[0])
                        b_c=int(b.split('-')[1])
                        rest1=b_r%simdsize
                        rest2=b_c%simdsize
                        if b_r>m:
                            b_r=m
                        if b_c>m:
                            b_c=m
                        if b_c%simdsize!=0:
                                b_c=b_c+simdsize-b_c%simdsize
                        equalshare1=math.ceil(m/b_r)
                        equalshare2=math.ceil(m/b_c) 
                        num_blocks=equalshare1*equalshare2
                        if th==1:
                            ratio=0
                        else:
                            ratio=str(num_blocks/(c*(th-1)))
                        mflop=0
                        if benchmark=='dmatdmatadd':                            
                            mflop=b_r*b_c                            
                        elif benchmark=='dmatdmatdmatadd':
                            mflop=b_r*b_c*2
                        else:
                            mflop=b_r*b_c*(2*m)
                        data_type=8
                        num_elements_uncomplete=0
                        if b_c<m:
                            num_elements_uncomplete=(m%b_c)*b_r
                            
                        if max_value-r<0.1*max_value:
                            num_elements=[mflop]*num_blocks
                            if num_elements_uncomplete:
                                for j in range(1,equalshare1+1):
                                    num_elements[j*equalshare2-1]=num_elements_uncomplete
                            data_type=8
                            grain_size=sum(num_elements[0:c])
                            if m<1000:
                                if grain_size<min_grain:
                                    min_grain=grain_size
                                if grain_size>max_grain:
                                    max_grain=grain_size
                            num_mat=3
                            if benchmark=='dmatdmatdmatadd':
                                num_mat=4
                            cost=c*mflop*num_mat/data_type
                            r=d_hpx[node][benchmark][th][b][c]['mflops'][k]
                            f_writer.writerow([node,benchmark,str(m),str(th),b.split('-')[0], 
                                               b.split('-')[1], str(b_r * b_c),str(num_elements_uncomplete), str(c),
                                               str(grain_size),str(num_blocks), str(num_blocks/c),
                                               str(b_r * b_c*c),str(num_blocks/th),ratio,L1cache,L2cache,L3cache,cache_line,set_associativity,str(data_type),str(cost),str(r)])
                if m<1000:

                    print('matrix size:'+str(m)+'   num_threads:'+str(th)+'   min_grain_size:'+str(min_grain)+'    max_grain_size:'+str(max_grain))                
                
                min_max_grain_size[node][benchmark][th][m]['min']=min_grain
                min_max_grain_size[node][benchmark][th][m]['max']=max_grain
f.close() 



for node in d_hpx.keys():  
    for benchmark in d_hpx[node].keys(): 
        for th in d_hpx[node][benchmark].keys():
            mins=[]
            maxs=[]
            for m in mat_sizes[benchmark]:
                mins.append(min_max_grain_size[node][benchmark][th][m]['min'])
                maxs.append(min_max_grain_size[node][benchmark][th][m]['max'])
            plt.figure(i)
            N = len(mat_sizes[benchmark])
            
            ind = np.arange(N)  # the x locations for the groups
            width = 1       # the width of the bars
            
            fig, ax = plt.subplots()
#            plt.axes([0, 0, 2, 1])
#
            rects1 = ax.bar(ind, mins, width, color='r')
            rects2 = ax.bar(ind, maxs, width, color='b')
            
            # add some text for labels, title and axes ticks
            ax.set_ylabel('Scores')
            ax.set_title('Min and Max grain size '+str(th)+' threads')
            ax.set_xticks(ind + width / 2)
            ax.set_xticklabels(('G1', 'G2', 'G3', 'G4', 'G5'))
            
            ax.legend((rects1[0], rects2[0]), ('Min', 'Max'))
            
            
            def autolabel(rects):
                """
                Attach a text label above each bar displaying its height
                """
                for rect in rects:
                    height = rect.get_height()
                    ax.text(rect.get_x() + rect.get_width()/2., 1.05*height,
                            '%d' % int(height),
                            ha='center', va='bottom')
#            
#            autolabel(rects1)
#            autolabel(rects2)
            
            plt.show()
            i=i+1
                
#convert -delay 50 step_*.png animated.gif
#################################################################
 #cache-miss based on block_size and matrix_size for chunk_size=1
#################################################################
c=1
animation=0
p3d=0
#plot number of cache misses based on matrix size for a chunk size and a block size
for benchmark in benchmarks:
    for th in d_hpx[node][benchmark].keys():
#        pp = PdfPages(perf_directory+'/bath_tub_'+benchmark+'_different_matrix_sizes_'+str(th)+'.pdf')
        results=[]
        bl=1
        block_sizes=[]
        m_sizes=[]
        avg_l2_miss_rate=[]
        real_block_sizes=[]
        for b in d_hpx[node][benchmark][th].keys():            
            for m in mat_sizes[benchmark]: 
                
                k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                    b_r=int(b.split('-')[0])
                    b_c=int(b.split('-')[1])
                    rest1=b_r%simdsize
                    rest2=b_c%simdsize
                    if b_r>m:
                        b_r=m
                    if b_c>m:
                        b_c=m
                    if b_c%simdsize!=0:
                        b_c=b_c+simdsize-b_c%simdsize
                    equalshare1=math.ceil(m/b_r)
                    equalshare2=math.ceil(m/b_c)  
                    chunk_sizes.append(c)
                    mflop=0
                    if 'add' in benchmark:                    
                        mflop=b_r*b_c                            
                    else:
                        mflop=b_r*b_c*(2*m)
                    m_sizes.append(m)
                    block_sizes.append(bl)
                    real_block_sizes.append(b)
                    results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k])
                    l2_cm.append(d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'])
                    l2_ch.append([d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][l]-d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][l] for l in range(th)])
                    ind_miss=[d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][j]/d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][j] for j in range(th)]
                    avg_l2_miss_rate.append(sum(ind_miss)/th)
            bl=bl+1
                    
        y=block_sizes
        x=m_sizes
        z=avg_l2_miss_rate
        if p3d:
            if not animation:
                fig = plt.figure(i)
    
                ax = fig.add_subplot(1,1,1, projection='3d')
                triang = mtri.Triangulation(x, y)
                
                ax.plot_trisurf(triang, z, cmap='jet')
                ax.scatter(x,y,z, marker='.', s=10, c="black", alpha=0.5)
                ax.view_init(elev=10, azim=110)
                ax.set_xlabel('Matrix size')
                ax.set_ylabel('Block size')
                ax.set_zlabel('L2 cache miss rate')
                plt.title(benchmark+'   matrix size:'+str(m)+'    '+str(th)+' threads')
    #            plt.savefig(pp, format='pdf',bbox_inches='tight')
                print('')
                i=i+1
            else:                    
    #                    surf=ax.plot_trisurf(y, x, z, cmap=plt.cm.viridis, linewidth=0.2)
    #                    fig.colorbar( surf, shrink=0.5, aspect=5)
    #                    ax.view_init(10, 60)
    #                    plt.show()
                
                for angle in range(0,360,10):
                    fig = plt.figure(i)
                    ax = fig.gca(projection='3d')
    
                    triang = mtri.Triangulation(x, y)
                    
                    ax.plot_trisurf(triang, z, cmap='jet')
                    ax.scatter(x,y,z, marker='.', s=10, c="black", alpha=0.5)
                    ax.view_init(elev=10, azim=angle)
                    ax.set_xlabel('Grain size')
                    ax.set_ylabel('Block size')
                    ax.set_zlabel('L2 cache miss rate')
                    plt.title(benchmark+'  chunk size:1  '+str(th)+' threads')
                    filename='/home/shahrzad/repos/Blazemark/results/png/step_'+str(angle)+'.png'
                    plt.savefig(filename, dpi=96)
                    plt.gca()
            if not animation:
                plt.show()
                pp.close()     
        else:
            plt.figure(i)
            plt.plot(real_block_sizes,z, label=str(th)+' threads  matrix_size:'+str(m))
            plt.ylabel('l2_cache_misse rate')
            plt.xlabel('block size')
            plt.title(benchmark+'  '+str(th)+' threads')
            plt.grid(True, 'both')
            plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)

#################################################################
 #cache-miss based on block_size and matrix_size for chunk_size=1
#################################################################
        
 
c=1
b='4-1024'
node='marvin'
benchmark='dmatdmatadd'
th=4
#plot number of cache misses based on matrix size for a chunk size and a block size
for benchmark in benchmarks:
    for th in d_hpx[node][benchmark].keys():
#        pp = PdfPages(perf_directory+'/bath_tub_'+benchmark+'_different_matrix_sizes_'+str(th)+'.pdf')
        results=[]
        for b in d_hpx[node][benchmark][th].keys():
            l2_cm=[]
            l2_ch=[]
            l2_miss_rate=[]

            for m in mat_sizes[benchmark]: 
                chunk_sizes=[]
                grain_sizes=[]
                k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                    b_r=int(b.split('-')[0])
                    b_c=int(b.split('-')[1])
                    rest1=b_r%simdsize
                    rest2=b_c%simdsize
                    if b_r>m:
                        b_r=m
                    if b_c>m:
                        b_c=m
                    if b_c%simdsize!=0:
                        b_c=b_c+simdsize-b_c%simdsize
                    equalshare1=math.ceil(m/b_r)
                    equalshare2=math.ceil(m/b_c)  
                    chunk_sizes.append(c)
                    
                    num_blocks=equalshare1*equalshare2
                    num_elements_uncomplete=0
                    if b_c<m:
                        num_elements_uncomplete=(m%b_c)*b_r
                    mflop=0
                    if benchmark=='dmatdmatadd':                            
                        mflop=b_r*b_c                            
                    elif benchmark=='dmatdmatdmatadd':
                        mflop=b_r*b_c*2
                    else:
                        mflop=b_r*b_c*(2*m)
                    num_elements=[mflop]*num_blocks
                    if num_elements_uncomplete:
                        for j in range(1,equalshare1+1):
                            num_elements[j*equalshare2-1]=num_elements_uncomplete
                    data_type=8
                    grain_size=sum(num_elements[0:c])
                    num_mat=3
                    if benchmark=='dmatdmatdmatadd':
                        num_mat=4
                    cost=c*mflop*num_mat/data_type
                    grain_sizes.append(grain_size)
                    results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k])
                    l2_cm.append(d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'])
                    l2_ch.append([d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][l]-d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][l] for l in range(th)])
                    l2_miss_rate.append([d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][j]/d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][j] for j in range(th)])

            if len(chunk_sizes)!=0:      
                for t in range(th):
                    tl=[l[t] for l in l2_miss_rate]
                    plt.figure(i+t)
                    plt.plot(mat_sizes[benchmark], tl, label=str(th)+' threads  block_size:'+str(b_r)+'-'+str(b_c)+'  num_blocks:'+str(equalshare1*equalshare2)+' block size '+str(b)+' core '+str(t))
                    plt.ylabel('l2_cache_misse rate')
                    plt.xlabel('matrix size')
                    plt.xscale('log')
                    plt.title(benchmark)
                    plt.grid(True, 'both')
                    plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
        i=i+th
#################################################################
 #cache-miss based on block_size and matrix_size for all chunk_sizes
#################################################################
for node in d_hpx.keys():
    #plot number of cache misses based on matrix size for a chunk size and a block size
    for benchmark in d_hpx[node].keys():
        for th in d_hpx[node][benchmark].keys():
    #        pp = PdfPages(perf_directory+'/bath_tub_'+benchmark+'_different_matrix_sizes_'+str(th)+'.pdf')
            results=[]
            for m in mat_sizes[benchmark]: 
                l2_cm=[]
                l2_ch=[]
                l2_miss_rate=[]
                grain_sizes=[]
                avg_l2_miss_rate=[]
                for b in d_hpx[node][benchmark][th].keys():

                    for c in d_hpx[node][benchmark][th][b].keys():
                        k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                        if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                            b_r=int(b.split('-')[0])
                            b_c=int(b.split('-')[1])
                            rest1=b_r%simdsize
                            rest2=b_c%simdsize
                            if b_r>m:
                                b_r=m
                            if b_c>m:
                                b_c=m
                            if b_c%simdsize!=0:
                                b_c=b_c+simdsize-b_c%simdsize
                            equalshare1=math.ceil(m/b_r)
                            equalshare2=math.ceil(m/b_c)  
                            chunk_sizes.append(c)
                            
                            num_blocks=equalshare1*equalshare2
                            num_elements_uncomplete=0
                            if b_c<m:
                                num_elements_uncomplete=(m%b_c)*b_r
                            mflop=0
                            if benchmark=='dmatdmatadd':                            
                                mflop=b_r*b_c                            
                            elif benchmark=='dmatdmatdmatadd':
                                mflop=b_r*b_c*2
                            else:
                                mflop=b_r*b_c*(2*m)
                            num_elements=[mflop]*num_blocks
                            if num_elements_uncomplete:
                                for j in range(1,equalshare1+1):
                                    num_elements[j*equalshare2-1]=num_elements_uncomplete
                            data_type=8
                            grain_size=sum(num_elements[0:c])
                            num_mat=3
                            if benchmark=='dmatdmatdmatadd':
                                num_mat=4
                            cost=c*mflop*num_mat/data_type
                            grain_sizes.append(grain_size)
                            results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k])
                            l2_cm.append(d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'])
                            l2_ch.append([d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][l]-d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][l] for l in range(th)])
                            l2_miss_rate.append([d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][j]/d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][j] for j in range(th)])
                            ind_miss=[d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][j]/d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][j] for j in range(th)]
                            avg_l2_miss_rate.append(sum(ind_miss)/th)
                    
                plt.figure(i)
                indices=np.argsort(np.array(grain_sizes))
                plt.plot([grain_sizes[i] for i in indices], [avg_l2_miss_rate[i] for i in indices], label=str(th)+' threads  matrix_size:'+str(m))
                plt.ylabel('l2_cache_misse rate')
                plt.xlabel('grain size')
                plt.xscale('log')
                plt.title(benchmark)
                plt.grid(True, 'both')
                plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
            i=i+1
            
        
(d_hpx,  chunk_sizes, block_sizes, thr, benchmarks, mat_sizes)=create_dict_relative_norepeat_counters_onebyone(papi_directory)                 
perf_directory='/home/shahrzad/repos/Blazemark/data/performance_plots/matrix/08-07-2019/performance_counters'

c=1
node='marvin'
benchmark='dmatdmatadd'
th=4
m=912
#plot number of cache misses based on block size for a chunk size and a matrix size
for node in d_hpx.keys():
    for benchmark in benchmarks:
#        pp = PdfPages(perf_directory+'/cache_miss_rate_'+benchmark+'_'+node+'.pdf')
        for th in d_hpx[node][benchmark].keys():

            for c in [1,2]:

                results=[]
                for m in mat_sizes[benchmark]: 
                    l2_cm=[]
                    l2_ch=[]
                    l2_miss_rate=[]
                    avg_l2_miss_rate=[]
        
                    block_sizes=[]
                    grain_sizes=[]
                    chunk_sizes=[]

                    for b in d_hpx[node][benchmark][th].keys():
                        k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                        if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                            b_r=int(b.split('-')[0])
                            b_c=int(b.split('-')[1])
                            rest1=b_r%simdsize
                            rest2=b_c%simdsize
                            if b_r>m:
                                b_r=m
                            if b_c>m:
                                b_c=m
                            if b_c%simdsize!=0:
                                b_c=b_c+simdsize-b_c%simdsize
                            equalshare1=math.ceil(m/b_r)
                            equalshare2=math.ceil(m/b_c)  
                            chunk_sizes.append(c)
                            num_blocks=equalshare1*equalshare2
                            num_elements_uncomplete=0
                            if b_c<m:
                                num_elements_uncomplete=(m%b_c)*b_r
                                
                            block_sizes.append(b)
                            mflop=0
                            if benchmark=='dmatdmatadd':                            
                                mflop=b_r*b_c                            
                            elif benchmark=='dmatdmatdmatadd':
                                mflop=b_r*b_c*2
                            else:
                                mflop=b_r*b_c*(2*m)
                            num_elements=[mflop]*num_blocks
                            if num_elements_uncomplete:
                                for j in range(1,equalshare1+1):
                                    num_elements[j*equalshare2-1]=num_elements_uncomplete
                            data_type=8
                            grain_size=sum(num_elements[0:c])
                            num_mat=3
                            if benchmark=='dmatdmatdmatadd':
                                num_mat=4
                            cost=c*mflop*num_mat/data_type
                            grain_sizes.append(grain_size)
        #                    block_sizes.append(str(b_r)+'-'+str(b_c))
                            results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k])
                            l2_cm.append(d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'])
                            l2_ch.append([d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][l]-d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][l] for l in range(th)])
                            ind_miss=[d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][j]/d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][j] for j in range(th)]
                            l2_miss_rate.append(ind_miss)
                            avg_l2_miss_rate.append(sum(ind_miss)/th)

                    if len(chunk_sizes)!=0:  
                        plt.figure(i)
                        plt.axes([0, 0, 2, 1])
                        plt.plot(block_sizes, avg_l2_miss_rate, label='matrix size:'+str(m))
                        plt.ylabel('L2_cache_misse rate')
                        plt.xlabel('block size')
                        plt.title(node+'  '+benchmark+' chunk_size: '+str(c)+'  '+str(th)+' threads')
                        plt.grid(True, 'both')
                        plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)    
                                              
                        
                        G=np.argsort(np.asarray(grain_sizes))
                        plt.figure(i+1)
                        plt.ylabel('L2_cache_misse rate')
                        plt.xlabel('grain size')
                        plt.title(node+'  '+benchmark+' chunk_size: '+str(c)+'  '+str(th)+' threads')
                        plt.grid(True, 'both')
                        plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)               
                        plt.plot([grain_sizes[g] for g in G], [avg_l2_miss_rate[g] for g in G], label='matrix size:'+str(m), marker='+')
                        plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)    
    
                        xs=[grain_sizes[g] for g in G]
                        ys=[avg_l2_miss_rate[g] for g in G]
                        zs=[block_sizes[g] for g in G]
                        for x,y,z in zip(xs,ys,zs):                
                            label = (z)                    
                            plt.annotate(label, # this is the text
                                         (x,y), # this is the point to label
                                         textcoords="offset points", # how to position the text
                                         xytext=(0,10), # distance from text to points (x,y)
                                         ha='center') # horizontal alignment can be left, right or center
                                         
#            plt.savefig(pp, format='pdf',bbox_inches='tight')
#            print('')
                i=i+2


        plt.show()
        pp.close()     

c=1
node='marvin'
benchmark='dmatdmatadd'
th=4
m=912
#plot number of cache misses based on block size for a matrix size and a chunk size
for node in d_hpx.keys():
    for benchmark in benchmarks:
#        pp = PdfPages(perf_directory+'/cache_miss_rate_'+benchmark+'_'+node+'.pdf')
        for th in d_hpx[node][benchmark].keys():
            for m in mat_sizes[benchmark]: 
                results=[]
                for c in d_hpx[node][benchmark][1]['4-1024'].keys():

                    l2_cm=[]
                    l2_ch=[]
                    l2_miss_rate=[]
                    avg_l2_miss_rate=[]
        
                    block_sizes=[]
                    grain_sizes=[]
                    chunk_sizes=[]

                    for b in d_hpx[node][benchmark][th].keys():
                        k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                        if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                            b_r=int(b.split('-')[0])
                            b_c=int(b.split('-')[1])
                            rest1=b_r%simdsize
                            rest2=b_c%simdsize
                            if b_r>m:
                                b_r=m
                            if b_c>m:
                                b_c=m
                            if b_c%simdsize!=0:
                                b_c=b_c+simdsize-b_c%simdsize
                            equalshare1=math.ceil(m/b_r)
                            equalshare2=math.ceil(m/b_c)  
                            chunk_sizes.append(c)
                            num_blocks=equalshare1*equalshare2
                            num_elements_uncomplete=0
                            if b_c<m:
                                num_elements_uncomplete=(m%b_c)*b_r
                                
                            block_sizes.append(b)
                            mflop=0
                            if benchmark=='dmatdmatadd':                            
                                mflop=b_r*b_c                            
                            elif benchmark=='dmatdmatdmatadd':
                                mflop=b_r*b_c*2
                            else:
                                mflop=b_r*b_c*(2*m)
                            num_elements=[mflop]*num_blocks
                            if num_elements_uncomplete:
                                for j in range(1,equalshare1+1):
                                    num_elements[j*equalshare2-1]=num_elements_uncomplete
                            data_type=8
                            grain_size=sum(num_elements[0:c])
                            num_mat=3
                            if benchmark=='dmatdmatdmatadd':
                                num_mat=4
                            cost=c*mflop*num_mat/data_type
                            grain_sizes.append(grain_size)
        #                    block_sizes.append(str(b_r)+'-'+str(b_c))
                            results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k])
                            l2_cm.append(d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'])
                            l2_ch.append([d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][l]-d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][l] for l in range(th)])
                            ind_miss=[d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][j]/d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][j] for j in range(th)]
                            l2_miss_rate.append(ind_miss)
                            avg_l2_miss_rate.append(sum(ind_miss)/th)

                    if len(chunk_sizes)!=0:  
                        plt.figure(i)
                        plt.axes([0, 0, 2, 1])
                        plt.plot(block_sizes, avg_l2_miss_rate, label='chunk size:'+str(c))
                        plt.ylabel('L2_cache_misse rate')
                        plt.xlabel('block size')
                        plt.title(node+'  '+benchmark+' matrix_size: '+str(m)+'  '+str(th)+' threads')
                        plt.grid(True, 'both')
                        plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)    
                                              
                        
                        G=np.argsort(np.asarray(grain_sizes))
                        plt.figure(i+1)
                        plt.ylabel('L2_cache_misse rate')
                        plt.xlabel('grain size')
                        plt.title(node+'  '+benchmark+' matrix_size: '+str(m)+'  '+str(th)+' threads')
                        plt.grid(True, 'both')
                        plt.plot([grain_sizes[g] for g in G], [avg_l2_miss_rate[g] for g in G], label='matrix size:'+str(m), marker='+')
                        plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)    
    
                        xs=[grain_sizes[g] for g in G]
                        ys=[avg_l2_miss_rate[g] for g in G]
                        zs=[block_sizes[g] for g in G]
                        for x,y,z in zip(xs,ys,zs):                
                            label = (z)                    
                            plt.annotate(label, # this is the text
                                         (x,y), # this is the point to label
                                         textcoords="offset points", # how to position the text
                                         xytext=(0,10), # distance from text to points (x,y)
                                         ha='center') # horizontal alignment can be left, right or center
                                         
#            plt.savefig(pp, format='pdf',bbox_inches='tight')
#            print('')
                i=i+2


        plt.show()
        pp.close()     

#plot number of cache misses based on chunk size for a matrix size and a block size
for node in d_hpx.keys():
    for benchmark in benchmarks:
        pp = PdfPages(perf_directory+'/cache_miss_rate_grain_size_'+benchmark+'_'+node+'.pdf')
        for th in d_hpx[node][benchmark].keys():
            for m in mat_sizes[benchmark]: 
                results=[]
                overall_avg_l2_miss_rate=[]
                overall_grain_sizes=[]
                for b in d_hpx[node][benchmark][th].keys():
                    l2_cm=[]
                    l2_ch=[]
                    l2_miss_rate=[]
                    avg_l2_miss_rate=[]
        
                    block_sizes=[]
                    grain_sizes=[]
                    chunk_sizes=[]
                    for c in d_hpx[node][benchmark][1]['4-1024'].keys():

                        k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                        if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                            b_r=int(b.split('-')[0])
                            b_c=int(b.split('-')[1])
                            rest1=b_r%simdsize
                            rest2=b_c%simdsize
                            if b_r>m:
                                b_r=m
                            if b_c>m:
                                b_c=m
                            if b_c%simdsize!=0:
                                b_c=b_c+simdsize-b_c%simdsize
                            equalshare1=math.ceil(m/b_r)
                            equalshare2=math.ceil(m/b_c)  
                            chunk_sizes.append(c)
                            num_blocks=equalshare1*equalshare2
                            num_elements_uncomplete=0
                            if b_c<m:
                                num_elements_uncomplete=(m%b_c)*b_r
                                
                            block_sizes.append(b)
                            mflop=0
                            if benchmark=='dmatdmatadd':                            
                                mflop=b_r*b_c                            
                            elif benchmark=='dmatdmatdmatadd':
                                mflop=b_r*b_c*2
                            else:
                                mflop=b_r*b_c*(2*m)
                            num_elements=[mflop]*num_blocks
                            if num_elements_uncomplete:
                                for j in range(1,equalshare1+1):
                                    num_elements[j*equalshare2-1]=num_elements_uncomplete
                            data_type=8
                            grain_size=sum(num_elements[0:c])
                            num_mat=3
                            if benchmark=='dmatdmatdmatadd':
                                num_mat=4
                            cost=c*mflop*num_mat/data_type
                            grain_sizes.append(grain_size)
        #                    block_sizes.append(str(b_r)+'-'+str(b_c))
                            results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k])
                            l2_cm.append(d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'])
                            l2_ch.append([d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][l]-d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][l] for l in range(th)])
                            ind_miss=[d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tcm'][j]/d_hpx[node][benchmark][th][b][c]['counters'][k]['avg']['papi_tca'][j] for j in range(th)]
                            l2_miss_rate.append(ind_miss)
                            avg_l2_miss_rate.append(sum(ind_miss)/th)
                            overall_avg_l2_miss_rate.append(sum(ind_miss)/th)
                            overall_grain_sizes.append(grain_size)
                    if len(chunk_sizes)!=0:  
                        plt.figure(i)
                        plt.axes([0, 0, 2, 1])
                        plt.plot(chunk_sizes, avg_l2_miss_rate, label='block size:'+str(b))
                        plt.ylabel('L2_cache_misse rate')
                        plt.xlabel('chunk size')
                        plt.xscale('log')
                        plt.title(node+'  '+benchmark+' matrix_size: '+str(m)+'  '+str(th)+' threads')
                        plt.grid(True, 'both')
                        plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)    
                                              
                        
                        G=np.argsort(np.asarray(grain_sizes))
                        plt.figure(i+1)
                        plt.ylabel('L2_cache_misse rate')
                        plt.xlabel('grain size')
                        plt.title(node+'  '+benchmark+' matrix_size: '+str(m)+'  '+str(th)+' threads')
                        plt.grid(True, 'both')
                        plt.plot([grain_sizes[g] for g in G], [avg_l2_miss_rate[g] for g in G], label='block size:'+str(b), marker='+')
                        plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)    
    
                        plt.figure(i+2)
                        plt.axes([0, 0, 2, 1])
                        plt.plot(grain_sizes, avg_l2_miss_rate, label='block size:'+str(b))
                        plt.ylabel('L2_cache_misse rate')
                        plt.xlabel('grain size')
                        plt.xscale('log')
                        plt.title(node+'  '+benchmark+' matrix_size: '+str(m)+'  '+str(th)+' threads')
                        plt.grid(True, 'both')
                        plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)    
                        
                        xs=[grain_sizes[g] for g in G]
                        ys=[avg_l2_miss_rate[g] for g in G]
                        zs=[block_sizes[g] for g in G]
                        for x,y,z in zip(xs,ys,zs):                
                            label = (z)                    
                            plt.annotate(label, # this is the text
                                         (x,y), # this is the point to label
                                         textcoords="offset points", # how to position the text
                                         xytext=(0,10), # distance from text to points (x,y)
                                         ha='center') # horizontal alignment can be left, right or center
                indices=np.argsort(np.asarray(overall_grain_sizes))
                plt.figure('1')
                plt.axes([0, 0, 2, 1])
                plt.plot([overall_grain_sizes[i] for i in indices], [overall_avg_l2_miss_rate[i] for i in indices], label='matrix size:'+str(m))
                plt.ylabel('L2_cache_misse rate')
                plt.xlabel('chunk size')
                plt.xscale('log')
                plt.title(node+'  '+benchmark+' matrix_size: '+str(m)+'  '+str(th)+' threads')
                plt.grid(True, 'both')
                plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)    
                                      
                plt.savefig(pp, format='pdf',bbox_inches='tight')
                print('')
                i=i+4


        plt.show()
        pp.close()     


perf_directory='/home/shahrzad/repos/Blazemark/data/performance_plots/06-13-2019/grain_size/'
###bath tub mflops_vs_grainsize_one-blocksize
i=1
for node in ['medusa','trillian']:#d_hpx.keys():
    for benchmark in d_hpx[node].keys():
        for th in d_hpx[node][benchmark].keys():
            pp = PdfPages(perf_directory+'/'+node+'_bath_tub_'+benchmark+'_different_matrix_sizes_'+str(th)+'.pdf')
    
            for m in mat_sizes[benchmark]: 
                plt.figure(i)
                for b in d_hpx[node][benchmark][th].keys():
    
                    results=[]
                    chunk_sizes=[]
                    grain_sizes=[]
                    for c in d_hpx[node][benchmark][th][b].keys():                    
                        k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                        if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                            b_r=int(b.split('-')[0])
                            b_c=int(b.split('-')[1])
                            rest1=b_r%simdsize
                            rest2=b_c%simdsize
                            if b_r>m:
                                b_r=m
                            if b_c>m:
                                b_c=m
                            if b_c%simdsize!=0:
                                b_c=b_c+simdsize-b_c%simdsize
                            equalshare1=math.ceil(m/b_r)
                            equalshare2=math.ceil(m/b_c)  
                            chunk_sizes.append(c)
                            num_blocks=equalshare1*equalshare2
                            num_elements_uncomplete=0
                            if b_c<m:
                                num_elements_uncomplete=(m%b_c)*b_r
                            mflop=0
                            if benchmark=='dmatdmatadd':                            
                                mflop=b_r*b_c                            
                            elif benchmark=='dmatdmatdmatadd':
                                mflop=b_r*b_c*2
                            else:
                                mflop=b_r*b_c*(2*m)
                            num_elements=[mflop]*num_blocks
                            if num_elements_uncomplete:
                                for j in range(1,equalshare1+1):
                                    num_elements[j*equalshare2-1]=num_elements_uncomplete
                            data_type=8
                            grain_size=sum(num_elements[0:c])
                            num_mat=3
                            if benchmark=='dmatdmatdmatadd':
                                num_mat=4
                            cost=c*mflop*num_mat/data_type
                            grain_sizes.append(grain_size)
                            results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k])
                    if len(chunk_sizes)!=0:                    
                        
    #                    plt.plot(chunk_sizes, results, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b)+'  num_blocks:'+str(equalshare1*equalshare2))
                        plt.plot(grain_sizes, results, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b_r)+'-'+str(b_c)+'  num_blocks:'+str(equalshare1*equalshare2))
                        plt.xlabel("grain_size")           
    
    #                    plt.xlabel("chunk_size")           
                        plt.ylabel('MFlops')
                        plt.xscale('log')
                        plt.title(benchmark)
                        plt.grid(True, 'both')
                        plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
                print('')     
                plt.savefig(pp, format='pdf',bbox_inches='tight')
                i=i+1
                    
            plt.show()
            pp.close() 


###bath tub mflops_vs_number_of_tasks_one-blocksize
i=1
for node in d_hpx.keys():
    for benchmark in d_hpx[node].keys():
        for th in d_hpx[node][benchmark].keys():
            pp = PdfPages(perf_directory+'/'+node+'_bath_tub_'+benchmark+'_different_matrix_sizes_'+str(th)+'_num_tasks.pdf')
    
            for m in mat_sizes[benchmark]: 
                plt.figure(i)
                for b in d_hpx[node][benchmark][th].keys():
    
                    results=[]
                    chunk_sizes=[]
                    grain_sizes=[]
                    num_tasks=[]
                    for c in d_hpx[node][benchmark][th][b].keys():                    
                        k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                        if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                            b_r=int(b.split('-')[0])
                            b_c=int(b.split('-')[1])
                            rest1=b_r%simdsize
                            rest2=b_c%simdsize
                            if b_r>m:
                                b_r=m
                            if b_c>m:
                                b_c=m
                            if b_c%simdsize!=0:
                                b_c=b_c+simdsize-b_c%simdsize
                            equalshare1=math.ceil(m/b_r)
                            equalshare2=math.ceil(m/b_c)  
                            chunk_sizes.append(c)
                            num_blocks=equalshare1*equalshare2
                            num_elements_uncomplete=0
                            if b_c<m:
                                num_elements_uncomplete=(m%b_c)*b_r
                            mflop=0
                            if benchmark=='dmatdmatadd':                            
                                mflop=b_r*b_c                            
                            elif benchmark=='dmatdmatdmatadd':
                                mflop=b_r*b_c*2
                            else:
                                mflop=b_r*b_c*(2*m)
                            num_elements=[mflop]*num_blocks
                            if num_elements_uncomplete:
                                for j in range(1,equalshare1+1):
                                    num_elements[j*equalshare2-1]=num_elements_uncomplete
                            num_tasks.append(np.ceil(num_blocks/c))
                            data_type=8
                            grain_size=sum(num_elements[0:c])
                            num_mat=3
                            if benchmark=='dmatdmatdmatadd':
                                num_mat=4
                            cost=c*mflop*num_mat/data_type
                            grain_sizes.append(grain_size)
                            results.append(1/d_hpx[node][benchmark][th][b][c]['mflops'][k])
                    if len(chunk_sizes)!=0:   
                        plt.figure(i)
                        plt.plot(grain_sizes, results, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b_r)+'-'+str(b_c)+'  num_blocks:'+str(equalshare1*equalshare2))
                        plt.xlabel("grain_size")           
    
    #                    plt.xlabel("chunk_size")           
                        plt.ylabel('1/MFlops')
                        plt.xscale('log')
                        plt.title(benchmark)
                        plt.grid(True, 'both')
                        plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
    #                    plt.plot(chunk_sizes, results, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b)+'  num_blocks:'+str(equalshare1*equalshare2))
                        plt.figure(i+1)                    
                        plt.plot(num_tasks, results, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b_r)+'-'+str(b_c)+'  num_blocks:'+str(equalshare1*equalshare2))
                        plt.xlabel("num_tasks")           
    
    #                    plt.xlabel("chunk_size")           
                        plt.ylabel('1/MFlops')
                        plt.xscale('log')
                        plt.title(benchmark)
                        plt.grid(True, 'both')
                        plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
                print('')     
                plt.savefig(pp, format='pdf',bbox_inches='tight')
                i=i+1
                    
            plt.show()
            pp.close() 


perf_directory='/home/shahrzad/repos/Blazemark/data/performance_plots/06-13-2019/grain_size/'
###bath tub mflops_vs_chunksize_one-blocksize
i=1
for node in d_hpx.keys():
    for benchmark in benchmarks:
        for th in d_hpx[node][benchmark].keys():
            pp = PdfPages(perf_directory+node+'_bath_tub_'+benchmark+'_different_matrix_sizes_'+str(th)+'.pdf')
    
            for m in mat_sizes[benchmark]: 
                plt.figure(i)
                for b in [b for b in d_hpx[node][benchmark][th] if b not in ['64-64']]:#d_hpx[node][benchmark][th].keys():
    
                    results=[]
                    chunk_sizes=[]
                    grain_sizes=[]
                    for c in d_hpx[node][benchmark][th][b].keys():                    
                        k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                        if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                            b_r=int(b.split('-')[0])
                            b_c=int(b.split('-')[1])
                            rest1=b_r%simdsize
                            rest2=b_c%simdsize
                            if b_r>m:
                                b_r=m
                            if b_c>m:
                                b_c=m
                            if b_c%simdsize!=0:
                                b_c=b_c+simdsize-b_c%simdsize
                            equalshare1=math.ceil(m/b_r)
                            equalshare2=math.ceil(m/b_c)  
                            chunk_sizes.append(c)
                            num_blocks=equalshare1*equalshare2
                            num_elements_uncomplete=0
                            if b_c<m:
                                num_elements_uncomplete=(m%b_c)*b_r
                            mflop=0
                            if benchmark=='dmatdmatadd':                            
                                mflop=b_r*b_c                            
                            elif benchmark=='dmatdmatdmatadd':
                                mflop=b_r*b_c*2
                            else:
                                mflop=b_r*b_c*(2*m)
                            num_elements=[mflop]*num_blocks
                            if num_elements_uncomplete:
                                for j in range(1,equalshare1+1):
                                    num_elements[j*equalshare2-1]=num_elements_uncomplete
                            data_type=8
                            grain_size=sum(num_elements[0:c])
                            num_mat=3
                            if benchmark=='dmatdmatdmatadd':
                                num_mat=4
                            cost=c*mflop*num_mat/data_type
                            grain_sizes.append(grain_size)
                            results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k])
                    if len(chunk_sizes)!=0:                    
                        
                        plt.scatter(chunk_sizes, results, label=str(int(th))+' threads  matrix_size:'+str(int(m))+'  block_size:'+str(b)+'  num_blocks:'+str(equalshare1*equalshare2))
#                        plt.plot(grain_sizes, results, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b_r)+'-'+str(b_c)+'  num_blocks:'+str(equalshare1*equalshare2))
#                        plt.plot(grain_sizes, results, label='block_size:'+str(b_r)+'-'+str(int(b_c))+'  num_blocks:'+str(equalshare1*equalshare2))

                        plt.xlabel("grain_size")           
    
    #                    plt.xlabel("chunk_size")           
                        plt.ylabel('MFlops')
                        plt.xscale('log')
#                        plt.title(benchmark)
                        plt.grid(True, 'both')
                        plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
                        plt.savefig('/home/shahrzad/src/Dissertation/images/fig9.png',dpi=300,bbox_inches='tight')
#
                print('')     
                plt.savefig(pp, format='pdf',bbox_inches='tight')
                i=i+1
                    
            plt.show()
            pp.close() 

import random

i=1
for node in d_hpx.keys():
    for benchmark in benchmarks:
        for m in [m for m in mat_sizes[benchmark] if m>700]: #[230., 300., 455., 690.,793.]: #
import random

            pp = PdfPages(perf_directory+node+'_bath_tub_'+benchmark+'_different_matrix_sizes_'+str(th)+'.pdf')
            plt.figure(i)
            number_of_colors = len(mat_sizes[benchmark])

            color = ["#"+''.join([random.choice('0123456789ABCDEF') for j in range(6)])
             for i in range(number_of_colors)]
            c_index=0
            for th in range(1,9):#d_hpx[node][benchmark].keys():

                results=[]
                chunk_sizes=[]
                grain_sizes=[]
                for b in [b for b in d_hpx[node][benchmark][th] if b not in ['64-64', '4-64']]:#d_hpx[node][benchmark][th].keys():
                    
                    for c in d_hpx[node][benchmark][th][b].keys():                    
                        k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                        if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                            b_r=int(b.split('-')[0])
                            b_c=int(b.split('-')[1])
                            rest1=b_r%simdsize
                            rest2=b_c%simdsize
                            if b_r>m:
                                b_r=m
                            if b_c>m:
                                b_c=m
                            if b_c%simdsize!=0:
                                b_c=b_c+simdsize-b_c%simdsize
                            equalshare1=math.ceil(m/b_r)
                            equalshare2=math.ceil(m/b_c)  
                            chunk_sizes.append(c)
                            num_blocks=equalshare1*equalshare2
                            num_elements_uncomplete=0
                            if b_c<m:
                                num_elements_uncomplete=(m%b_c)*b_r
                            mflop=0
                            if benchmark=='dmatdmatadd':                            
                                mflop=b_r*b_c                            
                            elif benchmark=='dmatdmatdmatadd':
                                mflop=b_r*b_c*2
                            else:
                                mflop=b_r*b_c*(2*m)
                            num_elements=[mflop]*num_blocks
                            if num_elements_uncomplete:
                                for j in range(1,equalshare1+1):
                                    num_elements[j*equalshare2-1]=num_elements_uncomplete
                            data_type=8
                            grain_size=sum(num_elements[0:c])
                            num_mat=3
                            if benchmark=='dmatdmatdmatadd':
                                num_mat=4
                            cost=c*mflop*num_mat/data_type
                            grain_sizes.append(grain_size)
                            results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k])
                        
#                    plt.plot(chunk_sizes, results, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b)+'  num_blocks:'+str(equalshare1*equalshare2))
#                        plt.plot(grain_sizes, results, label=str(th)+' threads  matrix_size:'+str(m)+'  block_size:'+str(b_r)+'-'+str(b_c)+'  num_blocks:'+str(equalshare1*equalshare2))
#                        plt.plot(grain_sizes, results, label='block_size:'+str(b_r)+'-'+str(int(b_c))+'  num_blocks:'+str(equalshare1*equalshare2))
#                plt.scatter(grain_sizes, results,label='matrix size:'+str(int(m)),color=color[c_index],marker='.')
                plt.scatter(grain_sizes, results,label=str(int(th))+' cores',color=color[c_index],marker='.')

                plt.xlabel("grain_size")           
                plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)

#                    plt.xlabel("chunk_size")           
                plt.ylabel('MFlops')
                plt.xscale('log')
#                plt.title(benchmark)
                plt.grid(True, 'both')
                c_index+=1
                plt.figure(i)
                plt.savefig('/home/shahrzad/src/Dissertation/images/fig13.png',dpi=300,bbox_inches='tight')
#
                print('')     
                plt.savefig(pp, format='pdf',bbox_inches='tight')
                i=i+1
                    
            plt.show()
            pp.close()             
##########################################
#3d plot
import randomfrom mpl_toolkits import mplot3d
import randomimport numpy as np
import matplotlib.pyplot as plt
fig = plt.figure()
ax = plt.axes(projection='3d')
ax = plt.axes(projection='3d')
##################import random########################

# Data for a three-dimensional line
zline = np.linspace(0, 15, 1000)
xline = np.sin(zline)
yline = np.cos(zline)
ax.plot3D(xline, yline, zline, 'gray')

# Data for three-dimensional scattered points
zdata = 15 * np.random.random(100)
xdata = np.sin(zdata) + 0.1 * np.random.randn(100)
ydata = np.cos(zdata) + 0.1 * np.random.randn(100)
ax.scatter3D(xdata, ydata, zdata, c=zdata, cmap='Greens');            
            
f=open('/home/shahrzad/repos/Blazemark/data/data_chunks.csv','w')
f_writer=csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
f_writer.writerow(['benchmark','matrix_size','num_threads','block_size_row','block_size_col','num_elements','chunk_size','num_blocks','mflops','num_blocks/chunk_size','num_elements*chunk_size','num_blocks/num_threads','num_blocks/(chunk_size*(num_threads-1))'])
            
max_results={}   
all_data=[]     
for benchmark in benchmarks: 
    max_results[benchmark]={}
    for th in d_hpx[benchmark].keys():
        max_results[benchmark][th]={}
        for m in mat_sizes[benchmark]:
            max_results[benchmark][th][m]=[] 
            results=[]
            chunk_sizes=[]
            bs=[]
            for b in d_hpx[benchmark][th].keys():
                for c in d_hpx[benchmark][th][b]:                    
                    k=d_hpx[benchmark][th][b][c]['size'].index(m)
                    if 'mflops' in d_hpx[benchmark][th][b][c].keys() and d_hpx[benchmark][th][b][c]['mflops'][k]:
                        chunk_sizes.append(c)
                        results.append(d_hpx[benchmark][th][b][c]['mflops'][k]) 
                        bs.append(b)
            if len(chunk_sizes)!=0:                
                max_value=max(results)
                
                for r in results:                    
                    chunk_size=chunk_sizes[results.index(r)]
                    b_size=bs[results.index(r)]
                    max_results[benchmark][th][m].append((chunk_size,b_size,r))
                    b_r=int(b_size.split('-')[0])
                    b_c=int(b_size.split('-')[1])
                    rest1=b_r%simdsize
                    rest2=b_c%simdsize
                    if b_r>m:
                        b_r=m
                    if b_c>m:
                        b_c=m
                    if b_c%simdsize!=0:
                        b_c=b_c+simdsize-b_c%simdsize
                    equalshare1=math.ceil(m/b_r)
                    equalshare2=math.ceil(m/b_c) 
                    num_blocks=equalshare1*equalshare2
                    if th==1:
                        ratio='NA'
                    else:
                        ratio=str(num_blocks/(chunk_size*(th-1)))
                    if benchmark=='dmatdmatadd':
                        all_data.append([m,th, (b_r * b_c), b_r,b_c,(chunk_size),
                                       (num_blocks), (num_blocks/chunk_size),
                                       (b_r * b_c*chunk_size),(num_blocks/th), r])
                    if max_value-r<0.1*max_value:
                        f_writer.writerow([benchmark,str(m),str(th),b_size.split('-')[0], 
                                           b_size.split('-')[1], str(b_r * b_c), str(chunk_size),
                                           str(num_blocks), str(r),str(num_blocks/chunk_size),
                                           str(b_r * b_c*chunk_size),str(num_blocks/th),ratio])
f.close()

#######just the max value
max_results={}   
all_data=[]     
for benchmark in benchmarks: 
    max_results[benchmark]={}
    for th in d_hpx[benchmark].keys():
        max_results[benchmark][th]={}
        for m in mat_sizes[benchmark]:
            max_results[benchmark][th][m]=[] 
            results=[]
            chunk_sizes=[]
            bs=[]
            for b in d_hpx[benchmark][th].keys():
                for c in d_hpx[benchmark][th][b]:                    
                    k=d_hpx[benchmark][th][b][c]['size'].index(m)
                    if 'mflops' in d_hpx[benchmark][th][b][c].keys() and d_hpx[benchmark][th][b][c]['mflops'][k]:
                        chunk_sizes.append(c)
                        results.append(d_hpx[benchmark][th][b][c]['mflops'][k]) 
                        bs.append(b)
            if len(chunk_sizes)!=0:                
                max_value=max(results)
                r=(max_value)
                chunk_size=chunk_sizes[results.index(r)]
                b_size=bs[results.index(r)]
                max_results[benchmark][th][m].append((chunk_size,b_size,r))
                b_r=int(b_size.split('-')[0])
                b_c=int(b_size.split('-')[1])
                rest1=b_r%simdsize
                rest2=b_c%simdsize
                if b_r>m:
                    b_r=m
                if b_c>m:
                    b_c=m
                if b_c%simdsize!=0:
                    b_c=b_c+simdsize-b_c%simdsize
                equalshare1=math.ceil(m/b_r)
                equalshare2=math.ceil(m/b_c) 
                num_blocks=equalshare1*equalshare2
                if th==1:
                    ratio='NA'
                else:
                    ratio=str(num_blocks/(chunk_size*(th-1)))
                if benchmark=='dmatdmatadd':
                    all_data.append([m,th, (b_r * b_c), b_r,b_c,(chunk_size),
                                   (num_blocks), (num_blocks/chunk_size),
                                   (b_r * b_c*chunk_size),(num_blocks/th), r])
                


##mflops_vs_chunksize_different-blocksizes            
for benchmark in benchmarks:        
    for th in d_hpx[benchmark].keys():
#        pp = PdfPages(perf_directory+'/'+benchmark+'_different_blocks_'+str(th)+'.pdf')
    
        for m in mat_sizes[benchmark]:
    
            plt.figure(i)
            for b in [b for b in d_hpx[node][benchmark][th] if b not in ['64-64']]:
                results=[]
                chunk_sizes=[]
                for c in d_hpx[node][benchmark][th][b]:                    
                    k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                    if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                        chunk_sizes.append(c)
                        results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k])
                if len(chunk_sizes)!=0:
                    b_r=int(b.split('-')[0])
                    b_c=int(b.split('-')[1])
                    rest1=b_r%simdsize
                    rest2=b_c%simdsize
                    if b_r>m:
                        b_r=m
                    if b_c>m:
                        b_c=m
                    if b_c%simdsize!=0:
                        b_c=b_c+simdsize-b_c%simdsize                        
                    equalshare1=math.ceil(m/b_r)
                    equalshare2=math.ceil(m/b_c)  
                    plt.figure(i)
                    plt.plot(chunk_sizes, results, label='block_size:'+str(b)+', num_blocks:'+str(equalshare1*equalshare2))

#                    plt.plot(chunk_sizes, results, label=str(int(th))+' threads matrix_size:'+str(m)+' block_size:'+str(b)+' num_blocks:'+str(equalshare1*equalshare2))
                    plt.xlabel("chunk_size")           
                    plt.ylabel('MFlops')
                    plt.xscale('log')
#                    plt.title(benchmark)
                    plt.grid(True, 'both')
                    plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
#            plt.savefig(pp, format='pdf',bbox_inches='tight')
            plt.savefig('/home/shahrzad/src/Dissertation/images/fig7.png',dpi=300,bbox_inches='tight')

            print('') 
            i=i+1
                        
        plt.show()
        pp.close()                  

#####performance        mflops_vs_matrixsize_one_block

c=1                     
for node in d_hpx.keys():
    for benchmark in d_hpx[node].keys():  
        for th in d_hpx[node][benchmark].keys():   
            results=[]
            plt.figure(i)

        #        pp = PdfPages(perf_directory+'/performance_'+benchmark+'_'+b+'-chunk_size_'+str(c)+'.pdf')
        
            for m in mat_sizes[benchmark]:  
               for b in d_hpx[node][benchmark][th].keys():    

                    for c in d_hpx[node][benchmark][th][b].keys():
                        k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                        if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]!=0:
                            results.append(d_hpx[node][benchmark][th][b][c]['mflops'][k])
                            print(m,k,th,b,c)
        
            plt.figure(i)
            plt.plot(mat_sizes[benchmark], results, label=str(th)+' threads block_size:'+str(b))
            plt.xlabel("matrix_size")           
            plt.ylabel('MFlops')
            plt.xscale('log')
            plt.title(benchmark)
            plt.grid(True, 'both')
            plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
#            plt.savefig(pp, format='pdf',bbox_inches='tight')
            print('')
            i=i+1
                                    
                plt.show()
                pp.close()      
        
#####performance        mflops_vs_matrixsize_different_blocksizes chunk_size=1
for c in [7]:                    
    for benchmark in benchmarks: 
        pp = PdfPages(perf_directory+'/performance_'+benchmark+'_different_blocks-chunk_size_'+str(c)+'.pdf')
    
        for th in d_hpx[benchmark].keys():   
    
            plt.figure(i)
            for b in block_sizes[benchmark]:
                results=[]
    
                for m in mat_sizes[benchmark]:  
                    k=d_hpx[benchmark][th][b][c]['size'].index(m)
                    if 'mflops' in d_hpx[benchmark][th][b][c].keys() :
                        results.append(d_hpx[benchmark][th][b][c]['mflops'][k])
    
                plt.figure(i)
                plt.plot(mat_sizes[benchmark], results, label=str(th)+' threads block_size:'+str(b))
                plt.xlabel("matrix_size")           
                plt.ylabel('MFlops')
                plt.xscale('log')
                plt.title(benchmark + ' chunk_size:'+str(c))
                plt.grid(True, 'both')
                plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
            plt.savefig(pp, format='pdf',bbox_inches='tight')
            print('')
            i=i+1
                                
        plt.show()
        pp.close()         
        
#####performance  different benchmarks        
for th in d_hpx[node][benchmark].keys():   
    for b in ['4-128', '4-256']:
#        pp = PdfPages(perf_directory+'/performance_dmatdmatadd_dmatdmatdmatadd_'+b+'_'+str(th)+'.pdf')
        plt.figure(i)
        s=''
        for benchmark in benchmarks:      

            results=[]

            for m in mat_sizes[benchmark]:  
                c=1                     
                k=d_hpx[node][benchmark][th][b][c]['size'].index(m)
                if 'mflops' in d_hpx[node][benchmark][th][b][c].keys() and d_hpx[node][benchmark][th][b][c]['mflops'][k]:
                    results.append((2*m**2)/d_hpx[node][benchmark][th][b][c]['mflops'][k])
                else:
                    results.append(0)

            plt.figure(i)
            plt.plot(mat_sizes[benchmark], results, label=benchmark+' '+str(th)+' threads block_size:'+str(b))
            plt.xlabel("matrix_size")           
            plt.ylabel('MFlops')
            plt.xscale('log')
            s+=benchmark+'-'
            plt.title(s[:-1])
            plt.grid(True, 'both')
            plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
#            plt.savefig(pp, format='pdf',bbox_inches='tight')
#        print('')
    i=i+1
                            
        plt.show()
        pp.close()  
      