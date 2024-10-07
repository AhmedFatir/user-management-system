import React, { useRef, useEffect, useState } from 'react';
import "./bot.css";
import hell from "../asstes/hell.png";
import forest from "../asstes/forest.png";
import graveyard from "../asstes/graveyard.png";
import useFetch from '../../../hooks/useFetch';
import GameLogic from './GameLogic';
import Loading from '../components/Loading';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

const Bot = () => {
    const { data: gameSettings, isLoading, error } = useFetch(`${BACKEND_URL}/api/game/game-settings/current-user/`);
    const [background, setBackground] = useState(null);
    const [paddle, setPaddle] = useState(null);
    const [keys, setKeys] = useState(null);
    const [username, setUserName] = useState('');
    useEffect(() => {
        if (!isLoading && gameSettings) {
            if (gameSettings.background === 'hell') {
                setBackground(hell);
            } else if (gameSettings.background === 'forest') {
                setBackground(forest);
            } else if (gameSettings.background === 'graveyard') {
                setBackground(graveyard);
            }
            setPaddle(gameSettings.paddle)
            setKeys(gameSettings.keys)
            setUserName(gameSettings.user_name)
        }
    }, [isLoading, gameSettings]);
    if (isLoading | !paddle | !keys) {
        <Loading/>
    }
    return (
        <div className="pingponggame-container" style={{ backgroundImage: `url(${background})` }}>
            {paddle && keys && username && <GameLogic paddleColor={paddle} keys={keys} username={username}/>}
        </div>
    );
};

export default Bot;
