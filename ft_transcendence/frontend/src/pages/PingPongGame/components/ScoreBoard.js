import React from 'react';
import './scoreboard.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

const ScoreBoard = ({ user1Score, user2Score, user1, user2 }) => {
    return (
        <div className="scoreboard-container">
                <span className="username">{user1.username}</span>
                <img src={`${BACKEND_URL}${user1.avatar}`} alt="User 1 Avatar" className="avatar" />
                <div className="score">
                    <p className="user-score">{user1Score}</p>
                </div>
                <span className='line'></span>
                <div className="score">
                    <p className="user-score">{user2Score}</p>
                </div>
                <img src={`${BACKEND_URL}${user2.avatar}`} alt="User 2 Avatar" className="avatar" />
                <span className="username">{user2.username}</span>
        </div>
    );
};

export default ScoreBoard;
