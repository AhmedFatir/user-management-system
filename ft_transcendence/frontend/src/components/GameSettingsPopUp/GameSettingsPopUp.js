import React, { useState, useContext } from "react";
import hell from "../../pages/Game/Game-assets/hell.png";
import forest from "../../pages/Game/Game-assets/forest.png";
import graveyard from "../../pages/Game/Game-assets/graveyard.png";
import leftArrow from './left.png';
import rightArrow from './right.png';
import leftPaddleArrow from '../../pages/Game/Game-assets/left-arrow.png';
import rightPaddleArrow from '../../pages/Game/Game-assets/right-arrow.png';
import sKey from '../../pages/Game/Game-assets/s.png';
import upKey from '../../pages/Game/Game-assets/up.png';
import downKey from '../../pages/Game/Game-assets/down.png';
import wKey from '../../pages/Game/Game-assets/w.png';
import "./GameSettingsPopUp.css";
import useFetch from "../../hooks/useFetch";
import useAuth from "../../hooks/useAuth";
import axios from "axios";
import { RealTimeContext } from "../../context/RealTimeProvider";
import { useTranslation } from 'react-i18next'


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

const GameSettingsPopUp = ({ onExit }) => {
    const {auth} = useAuth();
    const areasArray = [hell, forest, graveyard];
    const areasNames = ["hell", "forest", "graveyard"];
    const paddleColors = ['#BC4F00', '#036145', '#8D0202', '#002194'];
    const [currentAreaIndex, setCurrentAreaIndex] = useState(0);
    const [currentColorIndex, setCurrentColorIndex] = useState(0);
    const [selectedOption, setSelectedOption] = useState(null);
    const {setGameAccepted} = useContext(RealTimeContext);
    const { t } = useTranslation();



    const handleLeftClick = () => {
        const newIndex = (currentAreaIndex - 1 + areasArray.length) % areasArray.length;
        setCurrentAreaIndex(newIndex);
    };

    const handleRightClick = () => {
        const newIndex = (currentAreaIndex + 1) % areasArray.length;
        setCurrentAreaIndex(newIndex);
    };

    const handlePaddleLeftClick = () => {
        const newIndex = (currentColorIndex - 1 + paddleColors.length) % paddleColors.length;
        setCurrentColorIndex(newIndex);
    };

    const handlePaddleRightClick = () => {
        const newIndex = (currentColorIndex + 1) % paddleColors.length;
        setCurrentColorIndex(newIndex);
    };
    const handleSelectOption = (option) => {
        setSelectedOption(option);
    };
    const handleSubmit = async () => {
        const gameSettings = {
            background: areasNames[currentAreaIndex],
            paddle: paddleColors[currentColorIndex],
            keys: selectedOption,
            gameMode: "invite",
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
        setGameAccepted(true);
        onExit();
    }

    return (
        <div className="gameSettings-container">
            <h1>{t('Customize Your Game')}</h1>
            <div className="backgrounds-container">
                <img src={leftArrow} alt="Left" onClick={handleLeftClick} />
                <img src={areasArray[currentAreaIndex]} alt="Background" className="background-image" />
                <img src={rightArrow} alt="Right" onClick={handleRightClick} />
            </div>
            <div className="tools">
                <h2>{t('KEYS')}</h2>
                <div className="keys-selection">
                        <div className={`ws-container container ${selectedOption === 'ws' ? 'selectedOption' : ''}`} onClick={() => handleSelectOption('ws')}>
                            <img src={wKey} alt="" className='key' />
                            <img src={sKey} alt="" className='key' />
                        </div>
                        <div className={`up-down-container container ${selectedOption === 'up-down' ? 'selectedOption' : ''}`} onClick={() => handleSelectOption('up-down')}>
                            <img src={upKey} alt="" className='key' />
                            <img src={downKey} alt="" className='key' />
                        </div>
                </div>
            </div>
            <div className="paddle-colors-container">
                <img src={leftPaddleArrow} alt="Left" onClick={handlePaddleLeftClick} />
                <div className="paddle-color-preview" style={{ backgroundColor: paddleColors[currentColorIndex] }} />
                <img src={rightPaddleArrow} alt="Right" onClick={handlePaddleRightClick} />
            </div>
            <button onClick={handleSubmit} className="cancel-button">{t('Submit')}</button>
        </div>
    );
};

export default GameSettingsPopUp;
