import React, { useState } from "react";
import local from "../../Game-assets/local.png";
import invite from "../../Game-assets/invite.png";
import pongy from "../../Game-assets/pongy.png";
import random from "../../Game-assets/random.png";
import leftArrow from "../../Game-assets/leftFlesh.png";
import rightArrow from "../../Game-assets/rightFlesh.png";
import { useTranslation } from 'react-i18next'


const GameMode = ({ className, setSelectedMode }) => {
    const { t } = useTranslation();
    const modes = [
        { name: t("Invite"), img: invite },
        { name: t("Local"), img: local },
        { name: t("Pongy!"), img: pongy },
        { name: t("Random"), img: random },
    ];

    const [selectedModeIndex, setSelectedModeIndex] = useState(0);
    const handleLeftClick = () => {
        const newIndex = (selectedModeIndex === 0 ? modes.length - 1 : selectedModeIndex - 1);
        setSelectedModeIndex(newIndex);
        setSelectedMode(modes[newIndex].name);
    };

    const handleRightClick = () => {
        const newIndex = (selectedModeIndex === modes.length - 1 ? 0 : selectedModeIndex + 1);
        setSelectedModeIndex(newIndex);
        setSelectedMode(modes[newIndex].name);
    };

    return (
        <div className={`${className} gameModeContainer`}>
            <h1 className="title">{t('Game Mode')}</h1>
            <div className="mode-selector">
                <img 
                    src={leftArrow} 
                    className="arrow-icon" 
                    alt="Left Arrow" 
                    onClick={handleLeftClick} 
                />
                <div className="mode-display">
                    <div className="mode-image-container">
                        <img 
                            src={modes[selectedModeIndex].img} 
                            alt={modes[selectedModeIndex].name} 
                            className="mode-image" 
                        />
                    </div>
                </div>
                <img 
                    src={rightArrow} 
                    className="arrow-icon" 
                    alt="Right Arrow"
                    onClick={handleRightClick} 
                />
            </div>
                    <h1 className="mode-title">{modes[selectedModeIndex].name}</h1>
        </div>
    );
};

export default GameMode;
