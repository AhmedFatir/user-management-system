import React, { useEffect, useState } from 'react';
import './timeout.css';
const TimeOut = ({ onTimeout }) => {
    const [secondsLeft, setSecondsLeft] = useState(120);

    useEffect(() => {
        const timer = setInterval(() => {
            setSecondsLeft((prevSeconds) => prevSeconds - 1);
        }, 1000);
        return () => clearInterval(timer);
    }, []);

    useEffect(() => {
        if (secondsLeft === 0) {
            onTimeout();
        }
    }, [secondsLeft, onTimeout]);

    const formatTime = (seconds) => {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins} : ${secs < 10 ? '0' + secs : secs}`;
    };

    return (
        <div className="timeout-container">
            <p>{formatTime(secondsLeft)}</p>
        </div>
    );
};

export default TimeOut;
