import React from 'react';
import { useState, useEffect } from 'react';
import './lineChart.css'
import useAuth from '../../../hooks/useAuth';
import { Line } from 'react-chartjs-2';
import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend,
} from 'chart.js';

ChartJS.register(
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend
);

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

const LineChart = () => {
    const { auth }  = useAuth()
    const [chartData, setChartData] = useState({
        labels: [],
        datasets: [
            {
                data: [],
                fill: false,
                backgroundColor: '#F62943',
                borderColor: '#F62943',
            },
        ],
    });

    useEffect(() => {
        fetch(`${BACKEND_URL}/user/xp-history/`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${auth.accessToken}`
            }
        })
        .then(response => response.json())
        .then(data => {
            setChartData({
                labels: data.labels,
                datasets: [
                    {
                        data: data.xp,
                        fill: false,
                        backgroundColor: '#F62943',
                        borderColor: '#F62943',
                    },
                ],
            });
        })
        .catch(error => console.error('Error fetching XP history:', error));
    }, [auth.accessToken]);

    const options = {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: {
                beginAtZero: true,
                grid: {
                    display: true, 
                    color: 'rgba(200, 200, 200, 0.3)',
                    lineWidth: 1, 
                    borderDash: [5, 5], 
                },
            },
            x: {
                grid: {
                    display: false, 
                },
            },
        },
        plugins: {
            legend: {
                display: false,
            },
        },
    };

    return (
        <div className='chart-line'>
            <Line data={chartData} options={options} style={{ width: '100%', height: '100%' }}/>
        </div>
    )
        
};

export default LineChart;
