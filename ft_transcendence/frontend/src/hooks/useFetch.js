

import React, { useEffect, useRef, useState } from 'react'
import useAuth from './useAuth'

const useFetch = (endpoint) => {
    const [data, setData] = useState(null)
    const [isLoading, setIsLoading] = useState(false)
    const [error, setError] = useState(null)
    const abortControllerRef = useRef()
    const { auth }  = useAuth()

    useEffect(() => {
        const fetchData = async () => {
            abortControllerRef.current = new AbortController()
            const signal = abortControllerRef.current.signal;
            setIsLoading(true)
            try {
                const response = await fetch(endpoint, {
                    signal,
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${auth.accessToken}`
                    }
                });
                if (response.status === 403) {
                  
                    setError('You are blocked from viewing this content.');
                    setData(null);
                }else if(response.status === 404){
                    setError('User not found');
                    setData(null);
                }
                else{
                    const data = await response.json()
                    setData(data)
                    
                }
            }
            catch(e) {
                if(e.name === 'AbortError') {
                    console.log('error fetching data')
                } else {
                    setError(e.message)
                }
            } finally {
                setIsLoading(false)
            }
        }
        fetchData();
        return () => {
            if(abortControllerRef.current) {
                abortControllerRef.current.abort()
            }
        }
    }, [endpoint])
    return { data, isLoading, error };
}

export default useFetch