import React, { useState, useContext, useEffect } from 'react';
import Underground from './UnderGround';
import hell from '../../Game-assets/hell.png';
import forest from '../../Game-assets/forest.png';
import graveyard from '../../Game-assets/graveyard.png';
import LaunchButtons from './LaunchButtons';
import ToolsContainer from './ToolsContainer';
import GameMode from './GameMode';
import axios from 'axios';
import useAuth from "../../../../hooks/useAuth.js";
import Paddles from './Paddle.js';
const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;


const PingPong = () => {
    const { auth } = useAuth();
    const [selectedBackground, setSelectedBackground] = useState(null);
    const [selectedPaddle, setSelectedPaddle] = useState("#BC4F00");
    const [selectedKeys, setSelectedKeys] = useState(null);
    const [selectedMode, setSelectedMode] = useState("Invite");
    const deps = [selectedMode, selectedBackground, selectedKeys, selectedPaddle].filter(Boolean);


    useEffect(() => {
        console.log("Selected Data seted succefuly");
    },);
    const handleBackgroundSelect = (background) => {
        setSelectedBackground(background);
    };

    const handlePaddleSelect = (paddle) => {
        setSelectedPaddle(paddle);
    };

    const handleKeysSelect = (keys) => {
        setSelectedKeys(keys);
    };

    const handleModeSelect = (mode) => {
        setSelectedMode(mode);
    };

    const handleLaunchGame = async () =>{
        const gameSettings = {
            background: selectedBackground,
            paddle: selectedPaddle,
            keys: selectedKeys,
            gameMode: selectedMode,
        }
        try  {
            const response = await axios.post(`${BACKEND_URL}/api/game/game-settings/current-user/`, gameSettings, {
                headers : {
                    'Content-Type' : 'application/json',
                    'Authorization': `Bearer ${auth.accessToken}`,
                }
            });
            console.log("Game Settings saved", response.data);
        } catch (error) {
            console.log("Failed to save game settings");
        }
    }
    return (
        <div className="PingPong-container">
            <div className="game-cutomisation">
                <Underground 
                    hell={hell}
                    forest={forest}
                    graveyard={graveyard}
                    onBackgroundSelect={handleBackgroundSelect} 
                />
            </div>
            <div className="tools-section">
                <Paddles 
                    onPaddleSelect={handlePaddleSelect} 
                />
                <ToolsContainer 
                    className="toolsContainer" 
                    onPaddleSelect={handlePaddleSelect} 
                    onKeysSelect={handleKeysSelect}
                />
                <GameMode 
                    className="gameModeContainer" 
                    setSelectedMode={handleModeSelect}
                />
                <LaunchButtons 
                    selectedMode={selectedMode} 
                    selectedBackground={selectedBackground} 
                    selectedKeys={selectedKeys} 
                    selectedPaddle={selectedPaddle}
                    className="launchButtons-container"
                    onLaunch={handleLaunchGame}
                />
            </div>
        </div>
    );
};

export default PingPong;
